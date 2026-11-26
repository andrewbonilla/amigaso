'use strict';
const L = require('./_lib');

const key = col => 'amigaso:' + col;
/* HGETALL de Upstash devuelve [campo, valor, campo, valor, ...] */
function parseHash(flat) {
  const o = {};
  for (let i = 0; i < (flat || []).length; i += 2) { try { o[flat[i]] = JSON.parse(flat[i + 1]); } catch (e) { /* documento dañado: se omite */ } }
  return o;
}

/* GET  /api/data  -> {cfg, convs, cands, seg, canalMes}
   POST /api/data  {ops:[{col,id,doc}]} -> guarda (doc) o borra (doc:null) documentos sueltos */
module.exports = L.handler(async (req, res) => {
  L.requireAuth(req);

  if (req.method === 'GET') {
    const r = await L.redis(L.COLS.map(c => ['HGETALL', key(c)]));
    const out = {};
    L.COLS.forEach((c, i) => { out[c] = parseHash(r[i]); });
    out.cfg = out.cfg.main || null;
    if (out.cfg) delete out.cfg.cred;               // las credenciales nunca viajan al navegador
    return L.send(res, 200, out);
  }

  if (req.method === 'POST') {
    const { ops } = L.readBody(req);
    if (!Array.isArray(ops) || !ops.length || ops.length > L.MAX_OPS) throw new L.HttpError(400, 'Lista de operaciones inválida.');
    const cmds = ops.map(o => {
      if (!o || !L.COLS.includes(o.col) || typeof o.id !== 'string' || !L.ID_RE.test(o.id)) throw new L.HttpError(400, 'Operación inválida.');
      if (o.col === 'cfg' && o.id !== 'main') throw new L.HttpError(400, 'Operación inválida.');
      if (o.doc == null) return ['HDEL', key(o.col), o.id];
      if (typeof o.doc !== 'object' || Array.isArray(o.doc)) throw new L.HttpError(400, 'Documento inválido.');
      if (o.col === 'cfg') delete o.doc.cred;
      const json = JSON.stringify(o.doc);
      if (Buffer.byteLength(json) > L.MAX_DOC_BYTES) throw new L.HttpError(413, 'Un documento supera el tamaño permitido.');
      return ['HSET', key(o.col), o.id, json];
    });
    await L.redis(cmds);
    return L.send(res, 200, { ok: true, n: cmds.length });
  }

  throw new L.HttpError(405, 'Método no permitido.');
});
