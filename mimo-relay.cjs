// MiMo 订阅 -> OpenAI + Anthropic 双协议本地中继(通用版,零配置)
// 适用:任何已安装并登录 Xiaomi MiMo Desktop 的 Windows 用户,双击即用
//
// 凭据获取(全自动,无需手工导出):
//   %APPDATA%\Xiaomi MiMo\Local State -> os_crypt.encrypted_key
//   -> PowerShell DPAPI CryptUnprotectData(CurrentUser) -> AES-256-GCM 主密钥(仅内存,不落盘)
//   -> 复制 Network\Cookies(含 WAL) 到临时目录 -> node:sqlite 读 -> v10 AES-GCM 解 passToken/userId/cUserId
//   兜底: 环境变量 MIMO_COOKIES 指定 cookies-plain.json 文件模式(自动监视变更)
//
// 协议面:
//   OpenAI:    GET /v1/models, POST /v1/chat/completions(流式/非流式)
//   Anthropic: POST /v1/messages(流式 SSE/非流式), POST /v1/messages/count_tokens
//   其他:      GET /health(含凭据状态)
//
// 自动维护: 上游 401/403 自动重刷重试;每 30 分钟定时重刷;重刷失败自动重新提取凭据(App 重登录后自愈)
// 模型映射: 任意客户端模型名(claude-*/gpt-*/mimo-*) -> mimo-pro(云端白名单实测可用)
//
// 用法:
//   node mimo-relay.cjs           -> http://127.0.0.1:8317/v1 (端口: MIMO_RELAY_PORT)
//   OpenAI 工具:  base_url=http://127.0.0.1:8317/v1, api_key=任意
//   Claude Code:  ANTHROPIC_BASE_URL=http://127.0.0.1:8317  ANTHROPIC_AUTH_TOKEN=任意
//   日志文件: MIMO_RELAY_LOG=<路径> 追加写日志(自启模式下由安装脚本设置)
'use strict';
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const PORT = Number(process.env.MIMO_RELAY_PORT) || 8317;
const COOKIES_PATH = process.env.MIMO_COOKIES || ''; // 显式文件模式(可选)
const LOG_PATH = process.env.MIMO_RELAY_LOG || '';
const UPSTREAM = 'https://mimo-server-cn.xiaomimimo.com/api/route/chat/completions';
const ME_URL = 'https://mimo-server-cn.xiaomimimo.com/api/user/xiaomi/me';
const REAL_MODEL = 'mimo-pro'; // 默认:客户端传无法识别的名字时回落到此
// 云端实测可用名单(CN 区订阅,2026-09-24 探测):mimo-pro→mimo-v2.6-pro, mimo-flash→mimo-v2.6-flash;其余一律 400
const UPSTREAM_MODELS = ['mimo-pro', 'mimo-flash', 'mimo-v2.6-pro', 'mimo-v2.6-flash'];
// /v1/models 只展示云端真实名单;名单外的客户端模型名由 resolveModel 静默回落到 mimo-pro
const MODEL_ALIASES = [...UPSTREAM_MODELS];
function resolveModel(m) { return UPSTREAM_MODELS.includes(m) ? m : REAL_MODEL; }

function log(msg) {
  const line = `[relay ${new Date().toISOString()}] ${msg}`;
  console.log(line);
  if (LOG_PATH) { try { fs.appendFileSync(LOG_PATH, line + os.EOL); } catch {} }
}

// ---------- 凭据自动提取(报告22链:Local State -> DPAPI -> AES key -> Cookies v10) ----------
// 注意:App 运行时其 Cookies 库为独占锁,无法读取。策略:
//   1) App 未运行时实时提取(首次使用需完全退出一次 MiMo Desktop)
//   2) 提取成功后以 DPAPI(CurrentUser) 加密缓存到 %APPDATA%\mimo-relay\creds.dat,之后 App 运行与否均可启动
function mimoDataDir() { return path.join(process.env.APPDATA || '', 'Xiaomi MiMo'); }
function cachePath() { return path.join(process.env.APPDATA || '', 'mimo-relay', 'creds.dat'); }
function dpapiRoundTrip(b64data, mode) {
  const fn = mode === 'protect' ? 'Protect' : 'Unprotect';
  const ps = `Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String('${b64data}'); [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::${fn}($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))`;
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { windowsHide: true, timeout: 30000 },
      (err, stdout) => err ? reject(err) : resolve(Buffer.from(String(stdout).trim(), 'base64')));
  });
}
const dpapiUnprotect = (b64) => dpapiRoundTrip(b64, 'unprotect');
async function saveCache(creds) {
  try {
    const enc = await dpapiRoundTrip(Buffer.from(JSON.stringify(creds), 'utf8').toString('base64'), 'protect');
    fs.mkdirSync(path.dirname(cachePath()), { recursive: true });
    fs.writeFileSync(cachePath(), enc.toString('base64'));
    log('credential cache saved (DPAPI, CurrentUser)');
  } catch (e) { log('cache save failed: ' + e.message); }
}
async function loadCache() {
  try {
    const raw = fs.readFileSync(cachePath(), 'utf8').trim();
    if (!raw) return null;
    const dec = await dpapiUnprotect(raw);
    const creds = JSON.parse(dec.toString('utf8'));
    return creds && creds.passToken ? creds : null;
  } catch { return null; }
}
function decryptV10(ev, mk) {
  if (!ev || ev.length < 31) return null;
  const prefix = ev.subarray(0, 3).toString('utf8');
  if (prefix !== 'v10' && prefix !== 'v11') return null;
  const nonce = ev.subarray(3, 15), tag = ev.subarray(ev.length - 16), ct = ev.subarray(15, ev.length - 16);
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', mk, nonce);
    d.setAuthTag(tag);
    let plain = Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    // 新版 Chromium:明文前 32 字节为 host hash,剥离
    if (/[^\x20-\x7E]/.test(plain.slice(0, 8))) {
      const stripped = plain.slice(32);
      if (stripped && !/[^\x20-\x7E]/.test(stripped.slice(0, 8))) plain = stripped;
    }
    return plain;
  } catch { return null; }
}
async function extractCredentials() {
  const dir = mimoDataDir();
  const localState = JSON.parse(fs.readFileSync(path.join(dir, 'Local State'), 'utf8'));
  const encKeyB64 = localState && localState.os_crypt && localState.os_crypt.encrypted_key;
  if (!encKeyB64) throw new Error('Local State 无 os_crypt.encrypted_key');
  let blob = Buffer.from(encKeyB64, 'base64');
  if (blob.subarray(0, 5).toString('utf8') === 'DPAPI') blob = blob.subarray(5);
  const mk = await dpapiUnprotect(blob.toString('base64'));
  if (mk.length !== 32) throw new Error('DPAPI 解出密钥长度异常: ' + mk.length);

  const candidates = [
    path.join(dir, 'Network', 'Cookies'),
    path.join(dir, 'Partitions', 'xiaomi-account', 'Network', 'Cookies'),
  ];
  const { DatabaseSync } = require('node:sqlite');
  const creds = {};
  for (const src of candidates) {
    if (!fs.existsSync(src)) continue;
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mimo-relay-'));
    const dst = path.join(tmp, 'Cookies');
    try {
      for (const suf of ['', '-wal', '-shm']) {
        try { fs.copyFileSync(src + suf, dst + suf); } catch (e) { if (suf === '') throw e; }
      }
      // 读写模式打开临时副本:App 运行时源库处于 WAL 模式,只读打开无 -shm 会报 unable to open
      const db = new DatabaseSync(dst);
      let rows = [];
      try { rows = db.prepare("SELECT host_key, name, value, encrypted_value FROM cookies WHERE host_key LIKE '%xiaomi%'").all(); } finally { try { db.close(); } catch {} }
      for (const r of rows) {
        if (creds[r.name]) continue;
        let plain = r.value || '';
        if (!plain && r.encrypted_value) plain = decryptV10(Buffer.from(r.encrypted_value), mk) || '';
        if (plain && (r.name === 'passToken' || r.name === 'userId' || r.name === 'cUserId')) creds[r.name] = plain;
      }
    } catch (e) { log('read cookies db failed: ' + src + ' -> ' + e.message); }
    finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} }
  }
  if (!creds.passToken) throw new Error('未能提取 passToken(请确认 MiMo Desktop 已安装并登录)');
  return creds; // 仅存内存
}

// ---------- Cookie 会话管理 ----------
const jar = new Map();
function setCookies(arr, host) {
  if (!arr) return;
  for (const sc of Array.isArray(arr) ? arr : [arr]) {
    const [nv, ...attrs] = sc.split(';');
    const eq = nv.indexOf('='); if (eq < 0) continue;
    const name = nv.slice(0, eq).trim(), value = nv.slice(eq + 1).trim();
    let domain = host;
    for (const a of attrs) { const [k, v] = a.trim().split('='); if (k && k.toLowerCase() === 'domain' && v) domain = v.replace(/^\./, '').toLowerCase(); }
    if (value === '' || /max-age=0/i.test(sc)) { jar.delete(name + '|' + domain); continue; }
    jar.set(name + '|' + domain, { value, domain });
  }
}
function cookieHeader(host) {
  const items = [];
  for (const [k, v] of jar) if (host === v.domain || host.endsWith('.' + v.domain)) items.push(k.split('|')[0] + '=' + v.value);
  return items.join('; ');
}
function seedJar(creds) {
  for (const n of ['userId', 'passToken', 'cUserId']) if (creds[n]) jar.set(n + '|xiaomi.com', { value: creds[n], domain: 'xiaomi.com' });
}
let credSource = 'none';
let refreshing = null;
async function refreshSession(allowReextract) {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    // 装种子凭据:文件模式 > 实时提取(App 未运行窗口) > DPAPI 缓存
    try {
      if (COOKIES_PATH) {
        const cookies = JSON.parse(fs.readFileSync(COOKIES_PATH, 'utf8'));
        const g = (n) => (cookies.find(c => c.name === n) || {}).value || '';
        seedJar({ userId: g('userId'), passToken: g('passToken'), cUserId: g('cUserId') });
        credSource = 'file';
      } else {
        try {
          const creds = await extractCredentials();
          seedJar(creds);
          credSource = 'auto-dpapi';
          saveCache(creds);
        } catch (e) {
          const cached = await loadCache();
          if (cached) {
            seedJar(cached);
            credSource = 'cache';
            log('live extract unavailable (' + e.message + ') -> using DPAPI cached credentials');
          } else {
            throw new Error(e.message + '; no cache (first run requires MiMo Desktop fully exited once)');
          }
        }
      }
    } catch (e) { log('credential load failed: ' + e.message); return 0; }
    // me 端点 302 链自动落 serviceToken
    let cur = ME_URL;
    for (let i = 0; i <= 10; i++) {
      const u = new URL(cur);
      const headers = { 'User-Agent': 'mimo-relay/2.0' };
      const ck = cookieHeader(u.host); if (ck) headers.Cookie = ck;
      try {
        const resp = await fetch(cur, { headers, redirect: 'manual', signal: AbortSignal.timeout(20000) });
        setCookies(resp.headers.getSetCookie ? resp.headers.getSetCookie() : [], u.host);
        const loc = resp.headers.get('location');
        if ([301, 302, 303, 307, 308].includes(resp.status) && loc && i < 10) { cur = new URL(loc, cur).toString(); continue; }
        if (resp.status === 200) { log('session refreshed (source=' + credSource + ')'); return 200; }
        log('session refresh status=' + resp.status);
        // App 重新登录后凭据会变:自动模式重新提取一次
        if ((resp.status === 401 || resp.status === 403) && !COOKIES_PATH && allowReextract !== false) {
          log('re-extracting credentials...');
          try { seedJar(await extractCredentials()); return refreshSession(false); } catch (e) { log('re-extract failed: ' + e.message); }
        }
        return resp.status;
      } catch (e) { log('refresh hop error: ' + e.message); return 0; }
    }
    return 0;
  })().finally(() => { refreshing = null; });
  return refreshing;
}
async function upstream(payload, retried) {
  const resp = await fetch(UPSTREAM, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookieHeader('mimo-server-cn.xiaomimimo.com') },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(180000)
  });
  if ((resp.status === 401 || resp.status === 403) && !retried) {
    log('upstream ' + resp.status + ' -> refreshing session and retrying');
    await refreshSession();
    return upstream(payload, true);
  }
  return resp;
}

// ---------- Anthropic <-> OpenAI 转换 ----------
function anthropicToOpenAI(body) {
  const msgs = [];
  if (body.system) {
    const sys = typeof body.system === 'string' ? body.system
      : (Array.isArray(body.system) ? body.system.map(b => (b && b.text) || '').filter(Boolean).join('\n') : '');
    if (sys) msgs.push({ role: 'system', content: sys });
  }
  for (const m of body.messages || []) {
    const role = m.role === 'assistant' ? 'assistant' : 'user';
    let c = m.content;
    if (Array.isArray(c)) {
      const parts = [];
      for (const b of c) {
        if (!b) continue;
        if (b.type === 'text') parts.push(b.text || '');
        else if (b.type === 'tool_result') parts.push('[tool_result] ' + (typeof b.content === 'string' ? b.content : JSON.stringify(b.content || '').slice(0, 2000)));
        else if (b.type === 'tool_use') parts.push(`[tool_use ${b.name}] ` + JSON.stringify(b.input || {}));
      }
      c = parts.join('\n');
    }
    msgs.push({ role, content: String(c ?? '') });
  }
  return { model: resolveModel(body.model), messages: msgs, stream: !!body.stream };
}
function openAIToAnthropic(oai, clientModel) {
  const choice = (oai.choices && oai.choices[0]) || {};
  const text = (choice.message && choice.message.content) || '';
  return {
    id: 'msg_' + crypto.randomBytes(12).toString('hex'),
    type: 'message', role: 'assistant', model: clientModel || REAL_MODEL,
    content: [{ type: 'text', text }],
    stop_reason: choice.finish_reason === 'stop' ? 'end_turn' : (choice.finish_reason || 'end_turn'),
    stop_sequence: null,
    usage: { input_tokens: (oai.usage && oai.usage.prompt_tokens) || 0, output_tokens: (oai.usage && oai.usage.completion_tokens) || 0 }
  };
}
function sseWrite(res, event, data) { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }
async function anthropicStream(res, up, clientModel) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  const msgId = 'msg_' + crypto.randomBytes(12).toString('hex');
  sseWrite(res, 'message_start', { type: 'message_start', message: { id: msgId, type: 'message', role: 'assistant', model: clientModel || REAL_MODEL, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } });
  sseWrite(res, 'content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
  let outTokens = 0, inTokens = 0, stopReason = 'end_turn';
  const decoder = new TextDecoder();
  let buf = '', done = false;
  for await (const chunk of up.body) {
    buf += decoder.decode(chunk, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (data === '[DONE]') { done = true; break; }
      let j; try { j = JSON.parse(data); } catch { continue; }
      const ch = (j.choices && j.choices[0]) || {};
      const delta = ch.delta && ch.delta.content;
      if (delta) sseWrite(res, 'content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: delta } });
      if (ch.finish_reason) stopReason = ch.finish_reason === 'stop' ? 'end_turn' : ch.finish_reason;
      if (j.usage) { inTokens = j.usage.prompt_tokens || inTokens; outTokens = j.usage.completion_tokens || outTokens; }
    }
    if (done) break;
  }
  sseWrite(res, 'content_block_stop', { type: 'content_block_stop', index: 0 });
  sseWrite(res, 'message_delta', { type: 'message_delta', delta: { stop_reason: stopReason, stop_sequence: null }, usage: { input_tokens: inTokens, output_tokens: outTokens } });
  sseWrite(res, 'message_stop', { type: 'message_stop' });
  res.end();
}
function roughCountTokens(body) {
  let chars = 0;
  if (body.system) chars += typeof body.system === 'string' ? body.system.length : JSON.stringify(body.system).length;
  for (const m of body.messages || []) chars += typeof m.content === 'string' ? m.content.length : JSON.stringify(m.content || '').length;
  return { input_tokens: Math.max(1, Math.ceil(chars / 3)) };
}
function readBody(req, res, cb) {
  let body = '';
  req.on('data', c => { body += c; if (body.length > 4e6) req.destroy(); });
  req.on('end', () => {
    let p;
    try { p = JSON.parse(body || '{}'); } catch { res.writeHead(400); res.end('{"error":"bad json"}'); return; }
    cb(p);
  });
}

// ---------- HTTP 服务 ----------
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  if (req.method === 'GET' && url === '/v1/models') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ object: 'list', data: MODEL_ALIASES.map(id => ({ id, object: 'model', owned_by: 'xiaomi-mimo-relay' })) }));
    return;
  }
  if (req.method === 'GET' && (url === '/health' || url === '/v1/health')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, upstream: 'xiaomi-mimo', model: REAL_MODEL, credentialSource: credSource, time: new Date().toISOString() }));
    return;
  }
  if (req.method === 'POST' && url === '/v1/messages/count_tokens') {
    readBody(req, res, p => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(roughCountTokens(p))); });
    return;
  }
  if (req.method === 'POST' && (url === '/v1/messages' || url === '/v1/chat/completions')) {
    readBody(req, res, async payload => {
      const isAnthropic = url === '/v1/messages';
      const clientModel = typeof payload.model === 'string' ? payload.model : REAL_MODEL;
      const oaiPayload = isAnthropic ? anthropicToOpenAI(payload) : { ...payload, model: resolveModel(payload.model) };
      try {
        const up = await upstream(oaiPayload);
        if (isAnthropic && up.ok && oaiPayload.stream) { await anthropicStream(res, up, clientModel); return; }
        if (isAnthropic && up.ok) {
          const oai = await up.json();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(openAIToAnthropic(oai, clientModel)));
          return;
        }
        res.writeHead(up.status, { 'Content-Type': up.headers.get('content-type') || 'application/json' });
        if (up.body) { for await (const chunk of up.body) res.write(chunk); }
        res.end();
      } catch (e) {
        if (!res.headersSent) res.writeHead(502);
        res.end(JSON.stringify({ error: String((e && e.message) || e) }));
      }
    });
    return;
  }
  res.writeHead(404); res.end('{"error":"not found"}');
});

(async () => {
  const st = await refreshSession();
  log('session refresh status=' + st + (st === 200 ? '' : ' (calls auto-retry; if persistent, confirm MiMo Desktop is logged in)'));
  setInterval(() => refreshSession().catch(() => {}), 30 * 60 * 1000).unref();
  if (COOKIES_PATH) {
    try { fs.watchFile(COOKIES_PATH, { interval: 60000 }, () => { log('cookies file changed -> reloading'); refreshSession().catch(() => {}); }); } catch {}
  }
  server.listen(PORT, '127.0.0.1', () => log(`listening http://127.0.0.1:${PORT}/v1 (openai + anthropic, credential=${credSource})`));
})();
