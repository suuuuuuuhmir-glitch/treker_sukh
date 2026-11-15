'use strict';
/* МишкаФит: калории по фото еды.
   Функция для Яндекс Облака (Cloud Functions, Node.js 18+).
   Трекер шлёт сюда фото (JPEG в base64) и, если есть, подпись.
   Функция спрашивает модель и возвращает продукты с граммами и КБЖУ.
   Ключи от ИИ лежат только здесь, в переменных окружения, а не в приложении.

   Переменные окружения:
     PROVIDER        yandex | gigachat              (по умолчанию yandex)
     -- Яндекс --
     YANDEX_FOLDER   идентификатор каталога (b1g...)
     YANDEX_API_KEY  API-ключ сервисного аккаунта (можно не задавать,
                     если у функции есть сервисный аккаунт с ролью ai.languageModels.user)
     YANDEX_MODEL    qwen3.6-35b-a3b                (по умолчанию)
     -- GigaChat --
     GIGA_AUTH_KEY   «Ключ авторизации» из личного кабинета Studio
     GIGA_SCOPE      GIGACHAT_API_PERS              (по умолчанию, для физлица)
     GIGA_MODEL      GigaChat-2-Max                 (по умолчанию)
     GIGA_BASE       https://gigachat.devices.sberbank.ru/api/v1 (по умолчанию)
     Файл russian_trusted_root_ca.pem рядом с index.js (сертификат НУЦ Минцифры).
     -- Защита --
     FIREBASE_API_KEY ключ Firebase из трекера: пускаем только тех, кто вошёл в аккаунт.
                      Если не задан, функция открыта всем (только для своих тестов!)
     DAILY_LIMIT     сколько фото в день на человека (по умолчанию 15)
     TOTAL_LIMIT     сколько фото в день всего на один экземпляр функции (по умолчанию 500)
     ALLOW_ORIGINS   через запятую; по умолчанию mishkafit.ru и GitHub Pages
*/
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const env = k => (process.env[k] || '').trim();
const PROVIDER = (env('PROVIDER') || 'yandex').toLowerCase();
const DAILY_LIMIT = +env('DAILY_LIMIT') || 15;
const TOTAL_LIMIT = +env('TOTAL_LIMIT') || 500;
const ORIGINS = (env('ALLOW_ORIGINS') || 'https://mishkafit.ru,https://www.mishkafit.ru,https://suuuuuuuhmir-glitch.github.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const MAX_B64 = 2 * 1024 * 1024;   // ~1.5 МБ картинки; трекер жмёт фото до 1024 px, это ~150 КБ

/* ---------- ответы ---------- */
function cors(origin) {
  const ok = ORIGINS.includes(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin || '');
  return {
    'Access-Control-Allow-Origin': ok ? origin : ORIGINS[0],
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
const reply = (origin, status, obj) => ({
  statusCode: status,
  headers: { ...cors(origin), 'Content-Type': 'application/json; charset=utf-8' },
  body: JSON.stringify(obj),
});
class Fail extends Error { constructor(status, message) { super(message); this.status = status; } }

/* ---------- кто спрашивает ---------- */
const seen = new Map();   // idToken -> {uid, until}
async function whoIs(authHeader) {
  const key = env('FIREBASE_API_KEY');
  if (!key) return 'open';
  const t = String(authHeader || '').replace(/^Bearer\s+/i, '');
  if (!t) throw new Fail(401, 'Войди в аккаунт, чтобы считать еду по фото');
  const c = seen.get(t);
  if (c && c.until > Date.now()) return c.uid;
  const r = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(key), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: t }),
  }).catch(() => null);
  if (!r) throw new Fail(503, 'Не удалось проверить аккаунт, попробуй ещё раз');
  const j = await r.json().catch(() => ({}));
  const u = r.ok && j.users && j.users[0];
  if (!u) throw new Fail(401, 'Войди в аккаунт ещё раз');
  if (seen.size > 5000) seen.clear();
  seen.set(t, { uid: u.localId, until: Date.now() + 10 * 60 * 1000 });
  return u.localId;
}

/* ---------- лимиты (на экземпляр функции; для начала этого хватает) ---------- */
let day = '', perUser = new Map(), total = 0;
function spend(uid) {
  const d = new Date().toISOString().slice(0, 10);
  if (d !== day) { day = d; perUser = new Map(); total = 0; }
  const n = perUser.get(uid) || 0;
  if (uid !== 'open' && n >= DAILY_LIMIT) throw new Fail(429, `На сегодня лимит: ${DAILY_LIMIT} фото. Завтра снова можно`);
  if (total >= TOTAL_LIMIT) throw new Fail(429, 'Сегодня слишком много фото у всех, попробуй завтра');
  perUser.set(uid, n + 1); total++;
}
function refund(uid) {   // ИИ не ответил: попытка не считается
  const n = perUser.get(uid) || 0;
  if (n > 0) perUser.set(uid, n - 1);
  if (total > 0) total--;
}

/* ---------- вопрос к модели ---------- */
function prompt(goal, text) {
  return [
    'Ты помогаешь вести дневник питания' + (goal ? ' ' + goal : '') + '.',
    'На фото еда. Раздели её на отдельные продукты или блюда.',
    'Для каждого оцени вес в граммах в готовом виде, калории, белки, жиры и углеводы в граммах.',
    'Если на фото упаковка с этикеткой, бери цифры с этикетки.',
    'Если на фото нет еды, верни пустой список items и в note напиши, что еды не видно.',
    text ? 'Подпись пользователя: «' + String(text).slice(0, 300) + '». Учитывай её (например, вес или состав).' : '',
    'Ответь ТОЛЬКО JSON без пояснений и без markdown, ровно в таком виде:',
    '{"items":[{"name":"гречка","grams":200,"kcal":220,"protein":8,"fat":2,"carbs":42}],"note":"одна короткая фраза-совет или пустая строка"}',
    'Названия коротко, по-русски, с маленькой буквы.',
  ].filter(Boolean).join('\n');
}

function parseAnswer(s) {
  s = String(s || '').replace(/```(?:json)?/gi, '');
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Fail(502, 'ИИ ответил непонятно, попробуй ещё раз');
  let j;
  try { j = JSON.parse(s.slice(a, b + 1)); } catch (e) { throw new Fail(502, 'ИИ ответил непонятно, попробуй ещё раз'); }
  const num = (v, max) => { const n = Number(String(v).replace(',', '.')); return isFinite(n) && n >= 0 ? Math.min(n, max) : 0; };
  const items = (Array.isArray(j.items) ? j.items : []).slice(0, 15).map(x => ({
    name: String(x.name || x.n || 'еда').slice(0, 60),
    grams: Math.round(num(x.grams ?? x.g, 3000)),
    kcal: Math.round(num(x.kcal ?? x.calories, 5000)),
    protein: Math.round(num(x.protein, 500) * 10) / 10,
    fat: Math.round(num(x.fat, 500) * 10) / 10,
    carbs: Math.round(num(x.carbs, 1000) * 10) / 10,
  })).filter(x => x.kcal > 0 || x.grams > 0);
  return { items, note: String(j.note || '').slice(0, 200) };
}

/* --- Яндекс AI Studio (OpenAI-совместимый API) --- */
async function askYandex(b64, text, goal, context) {
  const folder = env('YANDEX_FOLDER');
  if (!folder) throw new Fail(500, 'Функция не настроена: нет YANDEX_FOLDER');
  const key = env('YANDEX_API_KEY');
  const iam = context && context.token && context.token.access_token;
  if (!key && !iam) throw new Fail(500, 'Функция не настроена: нет YANDEX_API_KEY и сервисного аккаунта');
  const model = env('YANDEX_MODEL') || 'qwen3.6-35b-a3b';
  const r = await fetch('https://ai.api.cloud.yandex.net/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: key ? 'Api-Key ' + key : 'Bearer ' + iam,
      'OpenAI-Project': folder,
    },
    body: JSON.stringify({
      model: model.startsWith('gpt://') ? model : `gpt://${folder}/${model}`,
      temperature: 0.2,
      max_tokens: 800,
      messages: [{ role: 'user', content: [
        { type: 'text', text: prompt(goal, text) },
        { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,' + b64 } },
      ] }],
    }),
  }).catch(() => null);
  if (!r) throw new Fail(503, 'ИИ сейчас недоступен, попробуй позже');
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    console.error('yandex', r.status, JSON.stringify(j).slice(0, 500));
    throw new Fail(502, 'ИИ не ответил (' + r.status + ')');
  }
  const m = j.choices && j.choices[0] && j.choices[0].message;
  return parseAnswer(m && (typeof m.content === 'string' ? m.content : (m.content || []).map(p => p.text || '').join('')));
}

/* --- GigaChat (Сбер) --- */
let gigaCa = null, gigaTok = null;
function gigaReq(url, opt, body) {
  if (!gigaCa) {
    let pem = '';
    for (const f of ['russian_trusted_root_ca.pem', 'russian_trusted_root_ca_pem.crt', 'russian_trusted_root_ca.cer']) {
      try { pem = fs.readFileSync(path.join(__dirname, f), 'utf8'); break; } catch (e) {}
    }
    if (!pem) throw new Fail(500, 'Функция не настроена: нет файла сертификата russian_trusted_root_ca.pem');
    gigaCa = [...tls.rootCertificates, pem];
  }
  return new Promise((resolve, reject) => {
    const q = https.request(url, { ...opt, ca: gigaCa, timeout: 60000 }, res => {
      const ch = [];
      res.on('data', d => ch.push(d));
      res.on('end', () => {
        const s = Buffer.concat(ch).toString('utf8');
        let j = null; try { j = JSON.parse(s); } catch (e) {}
        resolve({ status: res.statusCode, json: j, text: s });
      });
    });
    q.on('timeout', () => q.destroy(new Error('timeout')));
    q.on('error', reject);
    if (body) q.write(body);
    q.end();
  });
}
async function gigaToken() {
  if (gigaTok && gigaTok.exp > Date.now() + 60000) return gigaTok.t;
  const key = env('GIGA_AUTH_KEY');
  if (!key) throw new Fail(500, 'Функция не настроена: нет GIGA_AUTH_KEY');
  const body = 'scope=' + encodeURIComponent(env('GIGA_SCOPE') || 'GIGACHAT_API_PERS');
  const r = await gigaReq(env('GIGA_OAUTH') || 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      RqUID: crypto.randomUUID(), Authorization: 'Basic ' + key.replace(/^Basic\s+/i, ''), 'Content-Length': Buffer.byteLength(body) },
  }, body);
  if (r.status !== 200 || !r.json || !r.json.access_token) {
    console.error('giga oauth', r.status, r.text.slice(0, 300));
    throw new Fail(502, 'GigaChat не пустил: проверь ключ авторизации');
  }
  gigaTok = { t: r.json.access_token, exp: +r.json.expires_at || Date.now() + 25 * 60000 };
  return gigaTok.t;
}
async function askGiga(b64, text, goal) {
  const base = (env('GIGA_BASE') || 'https://gigachat.devices.sberbank.ru/api/v1').replace(/\/$/, '');
  const tok = await gigaToken();
  // 1) загрузить фото как файл
  const bnd = '----mf' + crypto.randomBytes(8).toString('hex');
  const img = Buffer.from(b64, 'base64');
  const form = Buffer.concat([
    Buffer.from(`--${bnd}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\ngeneral\r\n`),
    Buffer.from(`--${bnd}\r\nContent-Disposition: form-data; name="file"; filename="food.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
    img, Buffer.from(`\r\n--${bnd}--\r\n`),
  ]);
  const up = await gigaReq(base + '/files', {
    method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'multipart/form-data; boundary=' + bnd, 'Content-Length': form.length },
  }, form);
  if (up.status !== 200 || !up.json || !up.json.id) {
    console.error('giga upload', up.status, up.text.slice(0, 300));
    throw new Fail(502, 'GigaChat не принял фото (' + up.status + ')');
  }
  const fileId = up.json.id;
  try {
    // 2) спросить
    const body = JSON.stringify({
      model: env('GIGA_MODEL') || 'GigaChat-2-Max',
      temperature: 0.2, max_tokens: 800,
      messages: [{ role: 'user', content: prompt(goal, text), attachments: [fileId] }],
    });
    const r = await gigaReq(base + '/chat/completions', {
      method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json', Accept: 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, body);
    if (r.status !== 200 || !r.json) {
      console.error('giga chat', r.status, r.text.slice(0, 300));
      throw new Fail(r.status === 429 ? 429 : 502, r.status === 429 ? 'GigaChat занят, попробуй через минуту' : 'GigaChat не ответил (' + r.status + ')');
    }
    const m = r.json.choices && r.json.choices[0] && r.json.choices[0].message;
    return parseAnswer(m && m.content);
  } finally {
    // 3) удалить фото из хранилища Сбера, чтобы не копилось
    gigaReq(base + '/files/' + encodeURIComponent(fileId) + '/delete', { method: 'POST', headers: { Authorization: 'Bearer ' + tok } }).catch(() => {});
  }
}

/* ---------- вход ---------- */
module.exports.handler = async function (event, context) {
  const h = {};
  for (const [k, v] of Object.entries((event && event.headers) || {})) h[k.toLowerCase()] = v;
  const origin = h.origin || '';
  const method = (event && event.httpMethod) || 'POST';
  if (method === 'OPTIONS') return { statusCode: 204, headers: cors(origin), body: '' };
  if (method === 'GET') return reply(origin, 200, { ok: true, provider: PROVIDER });
  if (method !== 'POST') return reply(origin, 405, { error: 'Только POST' });
  let spent = null;
  try {
    let raw = (event && event.body) || '';
    if (event && event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
    let q;
    try { q = JSON.parse(raw); } catch (e) { throw new Fail(400, 'Плохой запрос'); }
    const b64 = String(q.image || '').replace(/^data:image\/\w+;base64,/, '');
    if (!b64) throw new Fail(400, 'Нет фото');
    if (b64.length > MAX_B64) throw new Fail(413, 'Фото слишком большое');
    if (!/^[A-Za-z0-9+/=\s]+$/.test(b64.slice(0, 2000))) throw new Fail(400, 'Фото повреждено');
    const uid = await whoIs(h.authorization);
    spend(uid); spent = uid;
    const goal = String(q.goal || '').slice(0, 120);
    const text = String(q.text || '').slice(0, 300);
    const out = PROVIDER === 'gigachat' ? await askGiga(b64, text, goal) : await askYandex(b64, text, goal, context);
    return reply(origin, 200, { ...out, provider: PROVIDER });
  } catch (e) {
    if (spent !== null) refund(spent);
    if (!(e instanceof Fail)) console.error(e);
    return reply(origin, e.status || 500, { error: e instanceof Fail ? e.message : 'Что-то сломалось, попробуй ещё раз' });
  }
};
// для тестов
module.exports._parseAnswer = parseAnswer;
