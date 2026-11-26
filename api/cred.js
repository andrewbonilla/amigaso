'use strict';
const L = require('./_lib');

/* POST /api/cred {u, p} -> cambia el usuario y la contraseña de acceso (se guardan con hash scrypt) */
module.exports = L.handler(async (req, res) => {
  L.requireAuth(req);
  if (req.method !== 'POST') throw new L.HttpError(405, 'Método no permitido.');
  const { u, p } = L.readBody(req);
  if (typeof u !== 'string' || typeof p !== 'string') throw new L.HttpError(400, 'Datos inválidos.');
  const user = u.trim();
  if (!user || user.length > 64) throw new L.HttpError(400, 'El usuario debe tener entre 1 y 64 caracteres.');
  if (p.length < 6 || p.length > 128) throw new L.HttpError(400, 'La contraseña debe tener entre 6 y 128 caracteres.');
  await L.storeCred(user, p);
  L.send(res, 200, { ok: true }, { 'Set-Cookie': L.sessionCookie(req, L.signToken(user), L.SESSION_SECONDS) });
});
