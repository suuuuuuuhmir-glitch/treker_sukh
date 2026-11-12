'use strict';
/* МишкаФит: аккаунты и копия данных в облаке.

   Yandex Cloud Function, среда Node.js 22, без npm-пакетов.
   Данные лежат в закрытом бакете Object Storage, функция ходит туда
   с IAM-токеном своего сервисного аккаунта (роль storage.editor).

   Переменные окружения:
     BUCKET   имя бакета, например mishkafit-data
     ORIGINS  адреса сайта через запятую (по умолчанию https://mishkafit.ru)

   Один POST-запрос на всё: тело — JSON {op, ...}. Content-Type text/plain,
   чтобы браузер не делал предварительный OPTIONS-запрос. Токен входа
   тоже передаётся в теле: заголовок Authorization платформа отрезает.

   В бакете:
     users/<sha256(email)>.json     {id, email, salt, hash, ver, created, fails, lockUntil}
     data/<id>.json                 {rev, savedAt, data}
     sessions/<sha256(token)>.json  {uid, ukey, ver, exp}
*/
const crypto = require('node:crypto');

const STORAGE = process.env.STORAGE_URL || 'https://storage.yandexcloud.net';
const BUCKET = process.env.BUCKET || '';
const ORIGINS = (process.env.ORIGINS || 'https://mishkafit.ru')
  .split(',').map(s => s.trim()).filter(Boolean);

const MAX_BODY = 3400000;          // платформа принимает до 3,5 МБ
const SESSION_DAYS = 365;
const LOCK_AFTER = 8;              // неверных паролей подряд
const LOCK_MS = 15 * 60 * 1000;
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

class Fail extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status; this.code = code; this.extra = extra || {};
  }
}

/* ---------- storage ---------- */
async function s3(iam, method, key, body) {
  const headers = { Authorization: 'Bearer ' + iam };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(`${STORAGE}/${BUCKET}/${key}`, { method, headers, body });
  if (method === 'GET') {
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`storage GET ${r.status}`);
    return r.json();
  }
  if (!r.ok && !(method === 'DELETE' && r.status === 404)) throw new Error(`storage ${method} ${r.status}`);
  return true;
}
const store = iam => ({
  get: k => s3(iam, 'GET', k),
  put: (k, v) => s3(iam, 'PUT', k, JSON.stringify(v)),
  del: k => s3(iam, 'DELETE', k),
});

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const userKey = email => `users/${sha(email)}.json`;
const dataKey = id => `data/${id}.json`;
const sessKey = token => `sessions/${sha(token)}.json`;

function scrypt(password, salt) {
  return new Promise((res, rej) =>
    crypto.scrypt(password, salt, 64, SCRYPT, (e, k) => (e ? rej(e) : res(k))));
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}
async function checkPassword(user, password) {
  const salt = Buffer.from(user ? user.salt : 'AAAAAAAAAAAAAAAAAAAAAA==', 'base64');
  const k = await scrypt(password, salt);   // и без аккаунта, чтобы время ответа не выдавало его
  if (!user) return false;
  const want = Buffer.from(user.hash, 'base64');
  return want.length === k.length && crypto.timingSafeEqual(want, k);
}

function cleanEmail(v) {
  const e = String(v || '').trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) {
    throw new Fail(400, 'email', 'Проверь адрес почты');
  }
  return e;
}
function cleanPassword(v, isNew) {
  const p = String(v || '');
  if (isNew && p.length < 8) throw new Fail(400, 'password', 'Пароль — минимум 8 символов');
  if (!p || p.length > 200) throw new Fail(400, 'password', 'Введи пароль');
  return p;
}
function cleanData(v) {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'object' || Array.isArray(v)) throw new Fail(400, 'data', 'Неверный формат данных');
  return v;
}

async function newSession(db, user, ukey) {
  const token = crypto.randomBytes(32).toString('base64url');
  await db.put(sessKey(token), {
    uid: user.id, ukey, ver: user.ver || 0,
    exp: Date.now() + SESSION_DAYS * 864e5,
  });
  return token;
}
async function auth(db, token) {
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) {
    throw new Fail(401, 'auth', 'Войди в аккаунт ещё раз');
  }
  const s = await db.get(sessKey(token));
  if (!s || s.exp < Date.now()) throw new Fail(401, 'auth', 'Войди в аккаунт ещё раз');
  const user = await db.get(s.ukey);
  if (!user || user.id !== s.uid || (user.ver || 0) !== s.ver) {
    throw new Fail(401, 'auth', 'Войди в аккаунт ещё раз');
  }
  return { user, ukey: s.ukey };
}
const dataOut = d => (d ? { rev: d.rev, savedAt: d.savedAt, data: d.data } : { rev: 0, savedAt: 0, data: null });

/* ---------- operations ---------- */
const ops = {
  async register(db, b) {
    const email = cleanEmail(b.email);
    const password = cleanPassword(b.password, true);
    const data = cleanData(b.data);
    const ukey = userKey(email);
    if (await db.get(ukey)) throw new Fail(409, 'exists', 'Такой аккаунт уже есть — войди в него');
    const user = { id: crypto.randomUUID(), email, ...(await hashPassword(password)), ver: 0, created: Date.now(), fails: 0, lockUntil: 0 };
    await db.put(ukey, user);
    let rev = 0;
    if (data) { rev = 1; await db.put(dataKey(user.id), { rev, savedAt: Date.now(), data }); }
    const token = await newSession(db, user, ukey);
    return { token, email, rev };
  },

  async login(db, b) {
    const email = cleanEmail(b.email);
    const password = cleanPassword(b.password, false);
    const ukey = userKey(email);
    const user = await db.get(ukey);
    if (user && user.lockUntil > Date.now()) {
      const min = Math.ceil((user.lockUntil - Date.now()) / 60000);
      throw new Fail(429, 'locked', `Слишком много попыток. Попробуй через ${min} мин.`);
    }
    if (!(await checkPassword(user, password))) {
      if (user) {
        user.fails = (user.fails || 0) + 1;
        if (user.fails >= LOCK_AFTER) { user.fails = 0; user.lockUntil = Date.now() + LOCK_MS; }
        await db.put(ukey, user);
      }
      throw new Fail(401, 'bad', 'Неверная почта или пароль');
    }
    if (user.fails || user.lockUntil) { user.fails = 0; user.lockUntil = 0; await db.put(ukey, user); }
    const token = await newSession(db, user, ukey);
    const d = await db.get(dataKey(user.id));
    return { token, email, rev: d ? d.rev : 0 };
  },

  async get(db, b) {
    const { user } = await auth(db, b.token);
    return dataOut(await db.get(dataKey(user.id)));
  },

  // baseRev — версия, от которой устройство делало изменения.
  // Если в облаке уже другая, отвечаем 409 и отдаём облачную копию.
  async put(db, b) {
    const { user } = await auth(db, b.token);
    const data = cleanData(b.data);
    if (!data) throw new Fail(400, 'data', 'Нет данных');
    const cur = await db.get(dataKey(user.id));
    const curRev = cur ? cur.rev : 0;
    if (b.baseRev !== curRev) throw new Fail(409, 'conflict', 'В аккаунте есть новые данные', dataOut(cur));
    const next = { rev: curRev + 1, savedAt: Date.now(), data };
    await db.put(dataKey(user.id), next);
    return { rev: next.rev, savedAt: next.savedAt };
  },

  async logout(db, b) {
    if (typeof b.token === 'string' && b.token.length <= 200) await db.del(sessKey(b.token));
    return { ok: true };
  },

  // Удаляет аккаунт и копию данных; все входы на других устройствах
  // перестают работать, потому что сессии ссылаются на удалённый аккаунт.
  async delete(db, b) {
    const { user, ukey } = await auth(db, b.token);
    await db.del(dataKey(user.id));
    await db.del(ukey);
    await db.del(sessKey(b.token));
    return { ok: true };
  },
};

/* ---------- HTTP ---------- */
function corsFor(origin) {
  const allow = ORIGINS.includes(origin) ? origin : ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
function reply(cors, status, obj) {
  return {
    statusCode: status,
    headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    body: JSON.stringify(obj),
    isBase64Encoded: false,
  };
}

module.exports.handler = async function (event, context) {
  const h = event.headers || {};
  const origin = h.Origin || h.origin || '';
  const cors = corsFor(origin);
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };
  if (event.httpMethod !== 'POST') return reply(cors, 405, { error: 'method', message: 'Только POST' });

  const iam = context && context.token && context.token.access_token;
  if (!iam || !BUCKET) {
    console.error('no IAM token or BUCKET: attach a service account and set BUCKET');
    return reply(cors, 500, { error: 'config', message: 'Сервер не настроен' });
  }

  let raw = event.body || '';
  if (event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
  if (raw.length > MAX_BODY) return reply(cors, 413, { error: 'size', message: 'Слишком много данных' });
  let body;
  try { body = JSON.parse(raw); } catch (e) { body = null; }
  if (!body || typeof body !== 'object') return reply(cors, 400, { error: 'json', message: 'Неверный запрос' });

  const op = Object.prototype.hasOwnProperty.call(ops, body.op) ? ops[body.op] : null;
  if (!op) return reply(cors, 400, { error: 'op', message: 'Неизвестная операция' });

  try {
    return reply(cors, 200, await op(store(iam), body));
  } catch (e) {
    if (e instanceof Fail) return reply(cors, e.status, { error: e.code, message: e.message, ...e.extra });
    console.error(e);
    return reply(cors, 500, { error: 'server', message: 'Ошибка сервера, попробуй позже' });
  }
};
