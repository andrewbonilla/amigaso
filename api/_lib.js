'use strict';
/* Utilidades compartidas del backend (el guion bajo evita que Vercel lo exponga como ruta). */
const crypto = require('crypto');

const COOKIE = 'amg_s';
const SESSION_SECONDS = 12 * 3600;            // la sesión dura 12 horas
const COLS = ['cfg', 'convs', 'cands', 'seg', 'canalMes'];
const ID_RE = /^[A-Za-z0-9_\-]{1,64}$/;
const MAX_DOC_BYTES = 900 * 1024;
const MAX_OPS = 50;
const MAX_FAILS = 10, FAIL_WINDOW = 15 * 60;   // 10 intentos fallidos por IP cada 15 min

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }

const kvUrl = () => (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const kvToken = () => process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const secret = () => process.env.SESSION_SECRET || kvToken();

/* Ejecuta varios comandos Redis en una sola petición (REST de Upstash). */
async function redis(cmds) {
  if (!kvUrl() || !kvToken()) throw new HttpError(500, 'Falta conectar la base de datos (Upstash Redis) en Vercel. Vea el README.');
  let r;
  try {
    r = await fetch(kvUrl() + '/pipeline', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + kvToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify(cmds)
    });
  } catch (e) { throw new HttpError(502, 'No se pudo contactar la base de datos.'); }
  if (!r.ok) throw new HttpError(502, 'La base de datos rechazó la petición (' + r.status + ').');
  const out = await r.json();
  return out.map(x => { if (x && x.error) throw new HttpError(502, 'Error de base de datos: ' + x.error); return x.result; });
}

function send(res, status, obj, headers) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  Object.entries(headers || {}).forEach(([k, v]) => res.setHeader(k, v));
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  const b = req.body;
  if (b == null || b === '') return {};
  if (typeof b === 'string') { try { return JSON.parse(b); } catch (e) { throw new HttpError(400, 'Cuerpo JSON inválido.'); } }
  return b;
}

/* ---- sesión: cookie HttpOnly con token firmado (HMAC-SHA256) ---- */
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const hmac = s => crypto.createHmac('sha256', secret()).update(s).digest('base64url');
function signToken(u) {
  const body = b64({ u, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS });
  return body + '.' + hmac(body);
}
function verifyToken(tok) {
  if (!tok || tok.indexOf('.') < 0) return null;
  const [body, sig] = tok.split('.');
  const good = Buffer.from(hmac(body)), got = Buffer.from(sig || '');
  if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() / 1000 ? p : null; } catch (e) { return null; }
}
function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : '';
}
const isHttps = req => (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https';
const sessionCookie = (req, tok, maxAge) =>
  `${COOKIE}=${tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}` + (isHttps(req) ? '; Secure' : '');
function requireAuth(req) {
  const p = verifyToken(getCookie(req, COOKIE));
  if (!p) throw new HttpError(401, 'Sesión no válida o vencida.');
  return p;
}

/* ---- credenciales: las de Vercel (APP_USER / APP_PASSWORD) o las cambiadas desde la plataforma (hash scrypt) ---- */
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const sameStr = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hashPass = (p, saltHex) => crypto.scryptSync(String(p), Buffer.from(saltHex, 'hex'), 32).toString('hex');

async function checkLogin(u, p) {
  const [raw] = await redis([['GET', 'amigaso:cred']]);
  if (raw) {
    const c = JSON.parse(raw);
    const okU = sameStr(u, c.u);
    const okP = sameStr(hashPass(p, c.salt), c.hash);
    return okU && okP;
  }
  if (!process.env.APP_USER || !process.env.APP_PASSWORD) throw new HttpError(500, 'Falta configurar APP_USER y APP_PASSWORD en Vercel. Vea el README.');
  const okU = sameStr(u, process.env.APP_USER);
  const okP = sameStr(p, process.env.APP_PASSWORD);
  return okU && okP;
}
async function storeCred(u, p) {
  const salt = crypto.randomBytes(16).toString('hex');
  await redis([['SET', 'amigaso:cred', JSON.stringify({ u, salt, hash: hashPass(p, salt) })]]);
}

/* ---- límite de intentos de login por IP ---- */
const clientIp = req => ((req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || (req.socket && req.socket.remoteAddress) || 'x';
const rlKey = req => 'amigaso:rl:' + clientIp(req);
async function assertNotLocked(req) {
  const [n] = await redis([['GET', rlKey(req)]]);
  if (Number(n) >= MAX_FAILS) throw new HttpError(429, 'Demasiados intentos. Espere unos minutos e intente de nuevo.');
}
const registerFail = req => redis([['INCR', rlKey(req)], ['EXPIRE', rlKey(req), FAIL_WINDOW]]);
const clearFails = req => redis([['DEL', rlKey(req)]]);

/* Envuelve un handler: captura errores y responde JSON. */
const handler = fn => async (req, res) => {
  try { await fn(req, res); }
  catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Error interno del servidor.' });
  }
};

module.exports = { COLS, ID_RE, MAX_DOC_BYTES, MAX_OPS, COOKIE, SESSION_SECONDS, HttpError, redis, send, readBody, signToken,
  sessionCookie, requireAuth, checkLogin, storeCred, assertNotLocked, registerFail, clearFails, handler };
