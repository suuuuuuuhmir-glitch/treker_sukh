'use strict';
/* МишкаФит: калории по фото еды.
   Функция для Яндекс Облака (Cloud Functions, Node.js 18+).
   Трекер шлёт сюда фото (JPEG в base64) и, если есть, подпись.
   Функция спрашивает модель и возвращает продукты с граммами и КБЖУ.
   Ключи от ИИ лежат только здесь, в переменных окружения, а не в приложении.

   Проверка в браузере:
     <ссылка функции>           версия и настройки
     <ссылка функции>?check=1   ещё и настоящий вопрос к ИИ про тестовое фото (чашка кофе, test-coffee.jpg)

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

const VERSION = '2026-11-27';
const env = k => (process.env[k] || '').trim();
const PROVIDER = (env('PROVIDER') || 'yandex').toLowerCase();
const DEFAULT_MODEL = 'qwen3.6-35b-a3b';
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
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Mf-Token',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}
const reply = (origin, status, obj) => ({
  statusCode: status,
  headers: { ...cors(origin), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  body: JSON.stringify(obj),
});
// code: короткий код причины, трекер показывает его мелко под ошибкой, чтобы по скрину было ясно, что сломалось.
class Fail extends Error {
  constructor(status, message, code, detail) { super(message); this.status = status; this.code = code || ''; this.detail = detail || ''; }
}

/* ---------- кто спрашивает ---------- */
const seen = new Map();   // idToken -> {uid, until}
// Яндекс вырезает заголовок Authorization до того, как запрос попадёт в функцию,
// поэтому трекер кладёт токен аккаунта в тело запроса (поле token).
async function whoIs(token) {
  const key = env('FIREBASE_API_KEY');
  if (!key) return 'open';
  const t = String(token || '').replace(/^Bearer\s+/i, '').trim();
  if (!t) throw new Fail(401, 'Войди в аккаунт, чтобы считать еду по фото', 'no_token');
  const c = seen.get(t);
  if (c && c.until > Date.now()) return c.uid;
  const r = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(key), {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: t }),
  }).catch(() => null);
  if (!r) throw new Fail(503, 'Не удалось проверить аккаунт, попробуй ещё раз', 'auth_net');
  const j = await r.json().catch(() => ({}));
  const u = r.ok && j.users && j.users[0];
  if (!u) throw new Fail(401, 'Войди в аккаунт ещё раз', 'bad_token');
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
  if (uid !== 'open' && n >= DAILY_LIMIT) throw new Fail(429, `На сегодня лимит: ${DAILY_LIMIT} фото. Завтра снова можно`, 'limit_user');
  if (total >= TOTAL_LIMIT) throw new Fail(429, 'Сегодня слишком много фото у всех, попробуй завтра', 'limit_all');
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
    'Ты нутрициолог и помогаешь вести дневник питания' + (goal ? ' ' + goal : '') + '.',
    'Посмотри на фото и найди всю еду и напитки. Каждое блюдо или продукт отдельным пунктом.',
    'Для каждого оцени вес в граммах в готовом виде (напитки в мл, пиши их как граммы), калории, белки, жиры и углеводы в граммах.',
    'Вес оценивай по размеру тарелки (обычная 24–26 см), ложек, рук и упаковок. Даже если не уверен, дай лучшую оценку и не отказывайся.',
    'Если на фото упаковка с этикеткой, бери цифры с этикетки.',
    'Если еды на фото нет, верни пустой список items, а в note коротко напиши, что видно.',
    text ? 'Подпись пользователя: «' + String(text).slice(0, 300) + '». Она важнее фото (например, вес или состав).' : '',
    'Сразу ответь ТОЛЬКО JSON, без рассуждений, пояснений и markdown, ровно в таком виде:',
    '{"items":[{"name":"гречка","grams":200,"kcal":220,"protein":8,"fat":2,"carbs":42}],"note":"одна короткая фраза-совет или пустая строка"}',
    'Числа пиши цифрами без единиц измерения. Названия коротко, по-русски, с маленькой буквы.',
  ].filter(Boolean).join('\n');
}
const question = (b64, text, goal) => [
  { type: 'text', text: prompt(goal, text) },
  { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,' + b64 } },
];

/* ---------- разбор ответа ---------- */
// Ищет с конца текста сбалансированный JSON (объект или массив), который проходит проверку ok.
function grabJson(s, open, close, ok) {
  for (let start = s.lastIndexOf(open); start >= 0; start = start > 0 ? s.lastIndexOf(open, start - 1) : -1) {
    let depth = 0, inStr = false, esc = false;
    for (let i = start; i < s.length; i++) {
      const ch = s[i];
      if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
      if (ch === '"') inStr = true;
      else if (ch === open) depth++;
      else if (ch === close && --depth === 0) {
        const raw = s.slice(start, i + 1);
        for (const t of [raw, raw.replace(/,\s*([}\]])/g, '$1')]) {   // вторая попытка без висячих запятых
          try { const j = JSON.parse(t); if (ok(j)) return j; } catch (e) {}
        }
        break;
      }
    }
  }
  return null;
}
// Число из того, что прислала модель: 200, "200", "200 г", "1,5", "150–200" (берём середину), "1 200".
function num(v, max) {
  let n;
  if (typeof v === 'number') n = v;
  else {
    const s = String(v == null ? '' : v).replace(/(\d)[\s\u00a0]+(?=\d{3}(?!\d))/g, '$1').replace(/(\d),(\d)/g, '$1.$2');
    const r = s.match(/(\d+(?:\.\d+)?)\s*[-–—]\s*(\d+(?:\.\d+)?)/);
    n = r ? (+r[1] + +r[2]) / 2 : +((s.match(/\d+(?:\.\d+)?/) || [])[0]);
  }
  return isFinite(n) && n > 0 ? Math.min(n, max) : 0;
}
const r1 = x => Math.round(x * 10) / 10;
// Достаёт продукты из текста модели. Терпит раздумья <think>…</think>, ```json, текст вокруг JSON.
// Возвращает null, если JSON с продуктами не нашёлся.
function parseAnswer(s) {
  s = String(s || '')
    .replace(/<think>[\s\S]*?<\/think>/gi, ' ')
    .replace(/^[\s\S]*<\/think>/i, ' ')   // конец раздумий без начала
    .replace(/<think>[\s\S]*$/i, ' ')     // раздумья оборвались, ответа после них нет
    .replace(/```(?:json)?/gi, ' ');
  let j = grabJson(s, '{', '}', x => x && typeof x === 'object' && !Array.isArray(x) && Array.isArray(x.items));
  if (!j) {
    const a = grabJson(s, '[', ']', x => Array.isArray(x) && x.some(y => y && typeof y === 'object' && !Array.isArray(y)));
    if (a) j = { items: a };
  }
  if (!j) return null;
  const items = j.items.filter(x => x && typeof x === 'object' && !Array.isArray(x)).slice(0, 15).map(x => {
    const it = {
      name: String(x.name || x.n || x.title || x.food || 'еда').trim().slice(0, 60),
      grams: Math.round(num(x.grams ?? x.g ?? x.weight ?? x.weight_g, 3000)),
      kcal: Math.round(num(x.kcal ?? x.calories ?? x.cal ?? x.energy, 5000)),
      protein: r1(num(x.protein ?? x.proteins ?? x.p, 500)),
      fat: r1(num(x.fat ?? x.fats ?? x.f, 500)),
      carbs: r1(num(x.carbs ?? x.carbohydrates ?? x.c, 1000)),
    };
    if (!it.kcal && (it.protein || it.fat || it.carbs)) it.kcal = Math.round(it.protein * 4 + it.fat * 9 + it.carbs * 4);
    return it;
  }).filter(x => x.kcal > 0 || x.grams > 0);
  return { items, note: String(j.note || j.comment || '').trim().slice(0, 200) };
}

/* --- Яндекс AI Studio (OpenAI-совместимый API) --- */
// Qwen 3.6 по умолчанию сначала «думает» (<think>…</think>), и раздумья входят в лимит токенов ответа.
// С прежним лимитом в 800 токенов модель не успевала дойти до ответа. Для фото еды раздумья не нужны,
// поэтому просим их выключить. Как именно это делается для Qwen у Яндекса, в документации не сказано,
// так что пробуем способы по очереди и запоминаем тот, что сработал.
const WAYS = [
  { id: 'effort', extra: { reasoning_effort: 'none' }, max: 1500, temp: 0.3 },
  { id: 'kwargs', extra: { chat_template_kwargs: { enable_thinking: false } }, max: 1500, temp: 0.3 },
  { id: 'think', extra: {}, max: 6000, temp: 0.6 },   // выключить не дали: место и на раздумья, и на ответ
];
let wayOk = null;            // способ, который сработал на этом экземпляре функции
let tokField = 'max_tokens'; // если Яндекс попросит, переходим на max_completion_tokens

function yandexSetup(context) {
  const folder = env('YANDEX_FOLDER');
  const key = env('YANDEX_API_KEY');
  const iam = context && context.token && context.token.access_token;
  const model = env('YANDEX_MODEL') || DEFAULT_MODEL;
  return { folder, key, iam, model, uri: model.startsWith('gpt://') ? model : `gpt://${folder}/${model}` };
}
function apiError(j) {
  const e = j && (j.error || j);
  return String((e && (e.message || e.msg || e.details)) || JSON.stringify(j || {})).slice(0, 300);
}
function statusFail(st, msg) {
  if (st === 429) return new Fail(429, 'ИИ сейчас занят, попробуй через минуту', 'ai_429', msg);
  if (st === 401 || st === 403 || st === 404) return new Fail(502, 'ИИ сейчас недоступен, попробуй позже', 'ai_' + st, msg);
  return new Fail(502, 'ИИ не ответил, попробуй ещё раз', 'ai_' + st, msg);
}

async function askYandex(content, deadline, context) {
  const s = yandexSetup(context);
  if (!s.folder) throw new Fail(500, 'Функция не настроена', 'no_folder', 'нет переменной YANDEX_FOLDER');
  if (!s.key && !s.iam) throw new Fail(500, 'Функция не настроена', 'no_auth', 'нет YANDEX_API_KEY и сервисного аккаунта у функции');
  const order = wayOk ? [WAYS.find(w => w.id === wayOk), ...WAYS.filter(w => w.id !== wayOk)] : WAYS.slice();
  let last = null, swapped = false;
  for (let k = 0; k < order.length; k++) {
    const way = order[k];
    const left = deadline - Date.now();
    if (left < 6000) break;
    const t0 = Date.now();
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), left - 1500);
    let r, j;
    try {
      r = await fetch('https://ai.api.cloud.yandex.net/v1/chat/completions', {
        method: 'POST',
        signal: ctl.signal,
        headers: {
          'Content-Type': 'application/json',
          Authorization: s.key ? 'Api-Key ' + s.key : 'Bearer ' + s.iam,
          'OpenAI-Project': s.folder,
          'x-folder-id': s.folder,
        },
        body: JSON.stringify({ model: s.uri, temperature: way.temp, [tokField]: way.max, ...way.extra, messages: [{ role: 'user', content }] }),
      });
      j = await r.json().catch(() => ({}));
    } catch (e) {
      if (ctl.signal.aborted) throw new Fail(504, 'ИИ думал слишком долго, попробуй ещё раз', 'ai_timeout', way.id);
      throw new Fail(503, 'ИИ сейчас недоступен, попробуй позже', 'ai_net', String(e && e.message || e).slice(0, 200));
    } finally {
      clearTimeout(timer);
    }
    const ms = Date.now() - t0;
    if (!r.ok) {
      const msg = apiError(j);
      console.log(JSON.stringify({ ai: 'yandex', way: way.id, status: r.status, ms, error: msg }));
      if (r.status === 400 || r.status === 422) {
        if (!swapped && /max_(completion_)?tokens/i.test(msg)) {   // не тот параметр длины: повторяем этот же способ с другим
          swapped = true; tokField = tokField === 'max_tokens' ? 'max_completion_tokens' : 'max_tokens'; k--; continue;
        }
        last = statusFail(r.status, msg);
        if (way.id !== 'think') continue;   // этот способ выключить раздумья не поддержан: пробуем следующий
      }
      throw last || statusFail(r.status, msg);
    }
    const ch = (j.choices && j.choices[0]) || {};
    const m = ch.message || {};
    const text = typeof m.content === 'string' ? m.content : Array.isArray(m.content) ? m.content.map(p => (p && p.text) || '').join('') : '';
    const u = j.usage || {};
    const think = (u.completion_tokens_details && u.completion_tokens_details.reasoning_tokens) || 0;
    const thought = think > 0 || /<think>/i.test(text) || !!(m.reasoning_content || m.reasoning);
    console.log(JSON.stringify({ ai: 'yandex', way: way.id, status: 200, ms, finish: ch.finish_reason, out: u.completion_tokens, think, thought, len: text.length, head: text.slice(0, 160) }));
    const ans = parseAnswer(text);
    if (ans) {
      wayOk = way.id;
      return { ...ans, way: way.id, ms, finish: ch.finish_reason || '', think, thought };
    }
    const cut = ch.finish_reason === 'length';
    last = new Fail(502, cut ? 'ИИ не успел ответить, попробуй ещё раз' : 'ИИ ответил непонятно, попробуй ещё раз',
      cut ? 'ai_length' : 'ai_nojson', `${way.id}: ${ch.finish_reason || '?'}, ${u.completion_tokens || '?'} ток., ${text.slice(0, 160)}`);
    if (!cut && !thought) break;   // раздумий не было, ответ просто не по формату: другие способы не помогут
  }
  throw last || new Fail(504, 'ИИ думал слишком долго, попробуй ещё раз', 'ai_timeout');
}

/* --- GigaChat (Сбер) --- */
let gigaCa = null, gigaTok = null;
function gigaReq(url, opt, body) {
  if (!gigaCa) {
    let pem = '';
    for (const f of ['russian_trusted_root_ca.pem', 'russian_trusted_root_ca_pem.crt', 'russian_trusted_root_ca.cer']) {
      try { pem = fs.readFileSync(path.join(__dirname, f), 'utf8'); break; } catch (e) {}
    }
    if (!pem) throw new Fail(500, 'Функция не настроена', 'no_ca', 'нет файла сертификата russian_trusted_root_ca.pem');
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
  if (!key) throw new Fail(500, 'Функция не настроена', 'no_giga_key', 'нет переменной GIGA_AUTH_KEY');
  const body = 'scope=' + encodeURIComponent(env('GIGA_SCOPE') || 'GIGACHAT_API_PERS');
  const r = await gigaReq(env('GIGA_OAUTH') || 'https://ngw.devices.sberbank.ru:9443/api/v2/oauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json',
      RqUID: crypto.randomUUID(), Authorization: 'Basic ' + key.replace(/^Basic\s+/i, ''), 'Content-Length': Buffer.byteLength(body) },
  }, body);
  if (r.status !== 200 || !r.json || !r.json.access_token) {
    console.error('giga oauth', r.status, r.text.slice(0, 300));
    throw new Fail(502, 'ИИ сейчас недоступен, попробуй позже', 'giga_auth', 'GigaChat не пустил: проверь ключ авторизации (' + r.status + ')');
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
    throw new Fail(502, 'ИИ не принял фото, попробуй ещё раз', 'giga_upload_' + up.status, up.text.slice(0, 200));
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
      throw new Fail(r.status === 429 ? 429 : 502, r.status === 429 ? 'ИИ сейчас занят, попробуй через минуту' : 'ИИ не ответил, попробуй ещё раз', 'giga_' + r.status, r.text.slice(0, 200));
    }
    const m = r.json.choices && r.json.choices[0] && r.json.choices[0].message;
    const ans = parseAnswer(m && m.content);
    if (!ans) throw new Fail(502, 'ИИ ответил непонятно, попробуй ещё раз', 'ai_nojson', String(m && m.content || '').slice(0, 160));
    return ans;
  } finally {
    // 3) удалить фото из хранилища Сбера, чтобы не копилось
    gigaReq(base + '/files/' + encodeURIComponent(fileId) + '/delete', { method: 'POST', headers: { Authorization: 'Bearer ' + tok } }).catch(() => {});
  }
}

/* ---------- самопроверка: GET ?check=1 ---------- */
let testJpeg = null;
try { testJpeg = fs.readFileSync(path.join(__dirname, 'test-coffee.jpg')).toString('base64'); } catch (e) {}
let checkDay = '', checks = 0;
async function selfCheck(context, deadline) {
  const d = new Date().toISOString().slice(0, 10);
  if (d !== checkDay) { checkDay = d; checks = 0; }
  if (++checks > 30) return { ai: 'skip', error: 'не больше 30 проверок в день' };
  const t0 = Date.now();
  try {
    let out;
    if (PROVIDER === 'gigachat') {
      if (!testJpeg) throw new Fail(500, 'Нет файла test-coffee.jpg рядом с index.js', 'no_test_photo');
      out = await askGiga(testJpeg, '', '');
    } else {
      out = await askYandex(testJpeg ? question(testJpeg, '', '')
        : [{ type: 'text', text: 'Проверка связи. Ответь только JSON: {"items":[],"note":"ок"}' }], deadline, context);
    }
    return { ai: 'ok', photo: !!testJpeg, ms: Date.now() - t0, ...out };
  } catch (e) {
    if (!(e instanceof Fail)) console.error(e);
    return { ai: 'error', ms: Date.now() - t0, code: e.code || '', error: e.message, detail: e.detail || '' };
  }
}

/* ---------- вход ---------- */
module.exports.handler = async function (event, context) {
  const t0 = Date.now();
  // функция живёт столько, сколько задано в её настройках (сейчас 1 минута); оставляем запас на ответ
  const left = context && typeof context.getRemainingTimeInMillis === 'function' ? +context.getRemainingTimeInMillis() : 0;
  const deadline = t0 + (left > 0 ? Math.max(5000, left - 4000) : 55000);
  const h = {};
  for (const [k, v] of Object.entries((event && event.headers) || {})) h[k.toLowerCase()] = v;
  const origin = h.origin || '';
  const method = (event && event.httpMethod) || 'POST';
  if (method === 'OPTIONS') return { statusCode: 204, headers: cors(origin), body: '' };
  if (method === 'GET') {
    const qs = (event && event.queryStringParameters) || {};
    const info = { ok: true, v: VERSION, provider: PROVIDER, accounts: !!env('FIREBASE_API_KEY') };
    if (PROVIDER === 'yandex') {
      const s = yandexSetup(context);
      Object.assign(info, { model: s.model, folder: !!s.folder, auth: s.key ? 'api-key' : s.iam ? 'service-account' : 'none' });
    }
    if (qs.check !== undefined) info.check = await selfCheck(context, deadline);
    return reply(origin, 200, info);
  }
  if (method !== 'POST') return reply(origin, 405, { error: 'Только POST' });
  let spent = null;
  try {
    // Трекер шлёт JSON как text/plain (так браузер не делает лишний запрос OPTIONS).
    // Яндекс может отдать тело строкой, строкой в base64 или уже готовым объектом.
    let q = event && event.body;
    if (typeof q === 'string' || !q) {
      let raw = q || '';
      if (event && event.isBase64Encoded) raw = Buffer.from(raw, 'base64').toString('utf8');
      try { q = JSON.parse(raw); } catch (e) { throw new Fail(400, 'Плохой запрос', 'bad_body'); }
    }
    if (!q || typeof q !== 'object') throw new Fail(400, 'Плохой запрос', 'bad_body');
    const b64 = String(q.image || '').replace(/^data:image\/\w+;base64,/, '');
    if (!b64) throw new Fail(400, 'Нет фото', 'no_photo');
    if (b64.length > MAX_B64) throw new Fail(413, 'Фото слишком большое', 'big_photo');
    if (!/^[A-Za-z0-9+/=\s]+$/.test(b64.slice(0, 2000))) throw new Fail(400, 'Фото повреждено', 'bad_photo');
    const uid = await whoIs(q.token || h['x-mf-token'] || h.authorization);
    spend(uid); spent = uid;
    const goal = String(q.goal || '').slice(0, 120);
    const text = String(q.text || '').slice(0, 300);
    const out = PROVIDER === 'gigachat' ? await askGiga(b64, text, goal) : await askYandex(question(b64, text, goal), deadline, context);
    console.log(JSON.stringify({ photo: 'ok', items: out.items.length, ms: Date.now() - t0 }));
    return reply(origin, 200, { items: out.items, note: out.note, provider: PROVIDER });
  } catch (e) {
    if (spent !== null) refund(spent);
    if (!(e instanceof Fail)) console.error(e);
    else console.log(JSON.stringify({ photo: 'fail', status: e.status, code: e.code, detail: e.detail, ms: Date.now() - t0 }));
    return reply(origin, e.status || 500, { error: e instanceof Fail ? e.message : 'Что-то сломалось, попробуй ещё раз', code: e.code || 'crash' });
  }
};
// для тестов
module.exports._parseAnswer = parseAnswer;
module.exports._num = num;
