'use strict';
const L = require('./_lib');

/* POST  /api/login  {u, p}  -> valida y abre sesión (cookie HttpOnly)
   DELETE /api/login          -> cierra sesión */
module.exports = L.handler(async (req, res) => {
  if (req.method === 'DELETE') return L.send(res, 200, { ok: true }, { 'Set-Cookie': L.sessionCookie(req, '', 0) });
  if (req.method !== 'POST') throw new L.HttpError(405, 'Método no permitido.');

  const { u, p } = L.readBody(req);
  if (typeof u !== 'string' || typeof p !== 'string' || !u || !p || u.length > 128 || p.length > 256) throw new L.HttpError(400, 'Escriba usuario y contraseña.');

  await L.assertNotLocked(req);
  if (!await L.checkLogin(u.trim(), p)) {
    await L.registerFail(req);
    throw new L.HttpError(401, 'Usuario o contraseña incorrectos');
  }
  await L.clearFails(req);
  L.send(res, 200, { ok: true }, { 'Set-Cookie': L.sessionCookie(req, L.signToken(u.trim()), L.SESSION_SECONDS) });
});
