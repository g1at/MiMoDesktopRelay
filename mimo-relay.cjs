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
//   OpenAI:    GET /v1/models, POST /v1/chat/completions(流式/非流式), POST /v1/responses, POST /v1/images/generations(文生图)
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
// 图像生成:独立端点(与 chat 同一套 passToken Cookie 鉴权 + X-Mimo-Source 头),实测 2026-09-24 出图正常
const UPSTREAM_IMAGES = 'https://mimo-server-cn.xiaomimimo.com/api/route/images/generations';
const IMAGE_MODELS = ['Doubao-Seedream-5.0-pro'];
function resolveImageModel(m) { return IMAGE_MODELS.includes(m) ? m : IMAGE_MODELS[0]; }
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
  let tried = 0, locked = 0;
  for (const src of candidates) {
    if (!fs.existsSync(src)) continue;
    tried++;
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
    } catch (e) {
      if (e.code === 'EBUSY' || e.code === 'EPERM') locked++;
      log('read cookies db failed: ' + src + ' -> ' + e.message);
    }
    finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} }
  }
  if (!creds.passToken) {
    // 任一候选库被独占锁(App 运行中)就可能藏有 passToken,报锁定而非引导检查安装/登录
    if (locked > 0) {
      throw new Error('Cookies 数据库被运行中的 MiMo Desktop 独占锁定(预期行为,无需退出 App)');
    }
    throw new Error('未能提取 passToken(请确认 MiMo Desktop 已安装并登录)');
  }
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
async function upstream(payload, retried, target, extraHeaders) {
  // 超时分两段:连接+首字节 180s(云端排队容忍);拿到响应头后解除总时限,
  // 流式 body 由 anthropicStream 的 idle 看门狗保护,非流式 body 由调用方 race 超时保护。
  // 旧实现 AbortSignal.timeout 覆盖整个流式生命周期,长响应 180s 必断连。
  const ctrl = new AbortController();
  const ttfb = setTimeout(() => ctrl.abort(), 180000);
  let resp;
  try {
    resp = await fetch(target || UPSTREAM, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader('mimo-server-cn.xiaomimimo.com'), ...(extraHeaders || {}) },
      body: JSON.stringify(payload),
      signal: ctrl.signal
    });
  } catch (e) { clearTimeout(ttfb); throw e; }
  clearTimeout(ttfb);
  if ((resp.status === 401 || resp.status === 403) && !retried) {
    log('upstream ' + resp.status + ' -> refreshing session and retrying');
    await refreshSession();
    return upstream(payload, true, target, extraHeaders);
  }
  return resp;
}

// ---------- Anthropic <-> OpenAI 转换 ----------
function mapFinishReason(fr) {
  return { stop: 'end_turn', length: 'max_tokens', tool_calls: 'tool_use', content_filter: 'refusal' }[fr] || 'end_turn';
}
function anthropicToOpenAI(body) {
  const msgs = [];
  if (body.system) {
    const sys = typeof body.system === 'string' ? body.system
      : (Array.isArray(body.system) ? body.system.map(b => (b && b.text) || '').filter(Boolean).join('\n') : '');
    if (sys) msgs.push({ role: 'system', content: sys });
  }
  for (const m of body.messages || []) {
    if (m.role === 'assistant') {
      let text = ''; const toolCalls = [];
      if (typeof m.content === 'string') text = m.content;
      else if (Array.isArray(m.content)) {
        for (const b of m.content) {
          if (!b) continue;
          if (b.type === 'text') text += (text ? '\n' : '') + (b.text || '');
          else if (b.type === 'tool_use') toolCalls.push({ id: b.id, type: 'function', function: { name: b.name, arguments: JSON.stringify(b.input || {}) } });
        }
      }
      const msg = { role: 'assistant', content: text || null };
      if (toolCalls.length) msg.tool_calls = toolCalls;
      msgs.push(msg);
      continue;
    }
    // user 消息:可能混有 text 与 tool_result;tool_result 拆成独立 role:tool 消息(OpenAI 语序),
    // image -> image_url part(多模态);flush 保持块内原始时序(text 在 tool_result 前时不会被翻到后面)
    if (Array.isArray(m.content)) {
      let texts = [], images = [];
      const flush = () => {
        if (!texts.length && !images.length) return;
        if (!images.length) { msgs.push({ role: 'user', content: texts.join('\n') }); }
        else {
          const content = [];
          const t = texts.join('\n'); if (t) content.push({ type: 'text', text: t });
          msgs.push({ role: 'user', content: content.concat(images) });
        }
        texts = []; images = [];
      };
      for (const b of m.content) {
        if (!b) continue;
        if (b.type === 'tool_result') {
          flush();
          let c = b.content;
          if (Array.isArray(c)) c = c.map(x => (x && x.text) || (x && x.type === 'image' ? '[image]' : typeof x === 'string' ? x : '')).filter(Boolean).join('\n');
          msgs.push({ role: 'tool', tool_call_id: b.tool_use_id, content: String(c ?? '') });
        }
        else if (b.type === 'text') texts.push(b.text || '');
        else if (b.type === 'image') {
          const s = b.source || {};
          if (s.type === 'base64' && s.data) images.push({ type: 'image_url', image_url: { url: `data:${s.media_type || 'image/png'};base64,${s.data}` } });
          else if (s.type === 'url' && s.url) images.push({ type: 'image_url', image_url: { url: s.url } });
          else texts.push('[image]');
        }
        else if (b.type === 'document') texts.push('[document]');
      }
      flush();
    } else {
      msgs.push({ role: 'user', content: String(m.content ?? '') });
    }
  }
  const out = { model: resolveModel(body.model), messages: msgs, stream: !!body.stream };
  if (body.max_tokens != null) out.max_tokens = body.max_tokens;
  if (body.temperature != null) out.temperature = body.temperature;
  if (body.top_p != null) out.top_p = body.top_p;
  if (Array.isArray(body.stop_sequences) && body.stop_sequences.length) out.stop = body.stop_sequences;
  // thinking.budget_tokens -> reasoning_effort(上游已实测接受该字段;disabled -> low)
  if (body.thinking) {
    if (body.thinking.type === 'enabled') {
      const b = body.thinking.budget_tokens || 0;
      out.reasoning_effort = b && b < 4096 ? 'low' : b && b < 16384 ? 'medium' : 'high';
    } else if (body.thinking.type === 'disabled') out.reasoning_effort = 'low';
  }
  if (Array.isArray(body.tools) && body.tools.length) {
    // 仅自定义工具可映射为 OpenAI function;服务端工具(web_search 等)上游不支持,丢弃
    const tools = body.tools.filter(t => t && (!t.type || t.type === 'custom'));
    if (tools.length) out.tools = tools.map(t => ({ type: 'function', function: { name: t.name, description: t.description || '', parameters: t.input_schema || { type: 'object', properties: {} } } }));
    const tc = body.tool_choice;
    if (tc) out.tool_choice = tc.type === 'auto' ? 'auto' : tc.type === 'any' ? 'required' : (tc.type === 'tool' && tc.name ? { type: 'function', function: { name: tc.name } } : 'auto');
  }
  return out;
}
// Anthropic usage:补 cache 字段(上游 prompt_tokens_details.cached_tokens -> cache_read_input_tokens)
function anthUsage(u) {
  u = u || {}; const pd = u.prompt_tokens_details || {};
  return { input_tokens: u.prompt_tokens || 0, output_tokens: u.completion_tokens || 0, cache_creation_input_tokens: 0, cache_read_input_tokens: pd.cached_tokens || 0 };
}
const genSig = () => crypto.randomBytes(96).toString('base64');
function openAIToAnthropic(oai, clientModel) {
  const choice = (oai.choices && oai.choices[0]) || {};
  const message = choice.message || {};
  const content = [];
  // reasoning_content -> thinking 块(带 signature;回传历史时客户端会原样带回,转换层会丢弃不参与上送)
  if (message.reasoning_content) content.push({ type: 'thinking', thinking: message.reasoning_content, signature: genSig() });
  if (message.content) content.push({ type: 'text', text: message.content });
  for (const tc of message.tool_calls || []) {
    let input = {};
    try { input = JSON.parse((tc.function && tc.function.arguments) || '{}'); } catch {}
    content.push({ type: 'tool_use', id: tc.id || ('toolu_' + crypto.randomBytes(8).toString('hex')), name: (tc.function && tc.function.name) || '', input });
  }
  if (!content.length) content.push({ type: 'text', text: '' });
  return {
    id: 'msg_' + crypto.randomBytes(12).toString('hex'),
    type: 'message', role: 'assistant', model: clientModel || REAL_MODEL,
    content,
    stop_reason: mapFinishReason(choice.finish_reason),
    stop_sequence: null,
    usage: anthUsage(oai.usage)
  };
}
function sseWrite(res, event, data) { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }
async function anthropicStream(res, up, clientModel) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  const msgId = 'msg_' + crypto.randomBytes(12).toString('hex');
  sseWrite(res, 'message_start', { type: 'message_start', message: { id: msgId, type: 'message', role: 'assistant', model: clientModel || REAL_MODEL, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 0, output_tokens: 0 } } });
  let outTokens = 0, inTokens = 0, cachedTokens = 0, stopReason = 'end_turn';
  // block 状态机:任意时刻最多一个 block 开着;text/thinking/tool_use 切换时先关后开
  let blockOpen = false, blockIndex = -1, blockType = null;
  const tcMap = new Map(); // OpenAI tool_calls index -> Anthropic blockIndex
  const closeBlock = () => {
    if (!blockOpen) return;
    try {
      // thinking 块收尾须先补 signature_delta(Anthropic 流式协议要求)
      if (blockType === 'thinking') sseWrite(res, 'content_block_delta', { type: 'content_block_delta', index: blockIndex, delta: { type: 'signature_delta', signature: genSig() } });
      sseWrite(res, 'content_block_stop', { type: 'content_block_stop', index: blockIndex });
    } catch {}
    blockOpen = false; blockType = null;
  };
  const openBlock = (type, cb) => { closeBlock(); blockIndex++; blockType = type; blockOpen = true; sseWrite(res, 'content_block_start', { type: 'content_block_start', index: blockIndex, content_block: cb }); };
  // 保活与看门狗:云端长推理期间定期 ping;超过 150s 无任何数据则判死断开(告别假断连)
  let lastChunk = Date.now(), finished = false;
  const pingTimer = setInterval(() => { try { sseWrite(res, 'ping', { type: 'ping' }); } catch {} }, 15000);
  const idleTimer = setInterval(() => {
    if (!finished && Date.now() - lastChunk > 150000) {
      log('upstream stream idle >150s, closing');
      try { sseWrite(res, 'error', { type: 'error', error: { type: 'timeout_error', message: 'upstream idle timeout' } }); sseWrite(res, 'message_stop', { type: 'message_stop' }); res.end(); } catch {}
      try { up.body.destroy(); } catch {}
    }
  }, 5000);
  try {
    const decoder = new TextDecoder();
    let buf = '', done = false;
    for await (const chunk of up.body) {
      lastChunk = Date.now();
      buf += decoder.decode(chunk, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (data === '[DONE]') { done = true; break; }
        let j; try { j = JSON.parse(data); } catch { continue; }
        const ch = (j.choices && j.choices[0]) || {};
        const delta = ch.delta || {};
        // reasoning_content -> thinking 块(thinking_delta 增量)
        if (delta.reasoning_content) {
          if (!blockOpen || blockType !== 'thinking') openBlock('thinking', { type: 'thinking', thinking: '' });
          sseWrite(res, 'content_block_delta', { type: 'content_block_delta', index: blockIndex, delta: { type: 'thinking_delta', thinking: delta.reasoning_content } });
        }
        if (delta.content) {
          if (!blockOpen || blockType !== 'text') openBlock('text', { type: 'text', text: '' });
          sseWrite(res, 'content_block_delta', { type: 'content_block_delta', index: blockIndex, delta: { type: 'text_delta', text: delta.content } });
        }
        for (const tc of delta.tool_calls || []) {
          const ti = tc.index != null ? tc.index : 0;
          let entry = tcMap.get(ti);
          // 先占位(关闭前一个块),content_block_start 延迟到 id/name 到达再发
          if (!entry) { closeBlock(); blockIndex++; entry = { blockIndex, started: false }; tcMap.set(ti, entry); }
          if (!entry.started && (tc.id || (tc.function && tc.function.name))) {
            sseWrite(res, 'content_block_start', { type: 'content_block_start', index: entry.blockIndex, content_block: { type: 'tool_use', id: tc.id || ('toolu_' + crypto.randomBytes(8).toString('hex')), name: (tc.function && tc.function.name) || '', input: {} } });
            entry.started = true; blockOpen = true; blockType = 'tool_use'; blockIndex = entry.blockIndex;
          }
          if (entry.started && tc.function && tc.function.arguments) {
            sseWrite(res, 'content_block_delta', { type: 'content_block_delta', index: entry.blockIndex, delta: { type: 'input_json_delta', partial_json: tc.function.arguments } });
          }
        }
        if (ch.finish_reason) stopReason = mapFinishReason(ch.finish_reason);
        if (j.usage) { const u = anthUsage(j.usage); inTokens = u.input_tokens || inTokens; outTokens = u.output_tokens || outTokens; cachedTokens = u.cache_read_input_tokens || cachedTokens; }
      }
      if (done) break;
    }
  } catch (e) {
    log('stream error: ' + e.message);
    // 流式中途异常:补 SSE error 事件,客户端可识别并走重试
    try { sseWrite(res, 'error', { type: 'error', error: { type: 'api_error', message: String((e && e.message) || e) } }); } catch {}
  }
  finished = true;
  clearInterval(pingTimer); clearInterval(idleTimer);
  closeBlock();
  try {
    sseWrite(res, 'message_delta', { type: 'message_delta', delta: { stop_reason: stopReason, stop_sequence: null }, usage: { input_tokens: inTokens, output_tokens: outTokens, cache_creation_input_tokens: 0, cache_read_input_tokens: cachedTokens } });
    sseWrite(res, 'message_stop', { type: 'message_stop' });
    res.end();
  } catch {}
}
// ---------- OpenAI Responses API 转换(新版 Codex 强制走 /v1/responses,已移除 chat 支持) ----------
function responsesToOpenAI(body) {
  const msgs = [];
  if (body.instructions) msgs.push({ role: 'system', content: body.instructions });
  const input = Array.isArray(body.input) ? body.input : (body.input ? [body.input] : []);
  for (const item of input) {
    if (typeof item === 'string') { msgs.push({ role: 'user', content: item }); continue; }
    if (!item || typeof item !== 'object') continue;
    if (item.type === 'function_call') {
      msgs.push({ role: 'assistant', content: null, tool_calls: [{ id: item.call_id || item.id, type: 'function', function: { name: item.name, arguments: typeof item.arguments === 'string' ? item.arguments : JSON.stringify(item.arguments || {}) } }] });
      continue;
    }
    if (item.type === 'function_call_output') {
      msgs.push({ role: 'tool', tool_call_id: item.call_id, content: typeof item.output === 'string' ? item.output : JSON.stringify(item.output ?? '') });
      continue;
    }
    if (item.type === 'message' || item.role) {
      const role = item.role === 'assistant' ? 'assistant' : (item.role === 'system' || item.role === 'developer' ? 'system' : 'user');
      let c = item.content;
      if (Array.isArray(c)) {
        const texts = [];
        for (const p of c) {
          if (!p) continue;
          if (p.type === 'input_text' || p.type === 'output_text' || p.type === 'text') texts.push(p.text || '');
          else if (p.type === 'input_image') texts.push('[image]');
        }
        c = texts.join('\n');
      }
      msgs.push({ role, content: String(c ?? '') });
    }
  }
  const out = { model: resolveModel(body.model), messages: msgs, stream: !!body.stream };
  if (body.max_output_tokens != null) out.max_tokens = body.max_output_tokens;
  if (body.temperature != null) out.temperature = body.temperature;
  if (body.top_p != null) out.top_p = body.top_p;
  if (Array.isArray(body.tools) && body.tools.length) {
    out.tools = body.tools.filter(t => t && t.type === 'function').map(t => ({ type: 'function', function: { name: t.name, description: t.description || '', parameters: t.parameters || { type: 'object', properties: {} } } }));
    if (typeof body.tool_choice === 'string') out.tool_choice = body.tool_choice;
  }
  return out;
}
function buildResponseObj(id, clientModel, status, output, usage) {
  return {
    id, object: 'response', created_at: Math.floor(Date.now() / 1000), status,
    model: clientModel || REAL_MODEL, output,
    usage: usage ? { input_tokens: usage.input_tokens || 0, output_tokens: usage.output_tokens || 0, total_tokens: (usage.input_tokens || 0) + (usage.output_tokens || 0) } : undefined
  };
}
function openAIToResponses(oai, clientModel) {
  const choice = (oai.choices && oai.choices[0]) || {};
  const message = choice.message || {};
  const output = [];
  if (message.content) {
    output.push({ type: 'message', id: 'msg_' + crypto.randomBytes(8).toString('hex'), role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: message.content, annotations: [] }] });
  }
  for (const tc of message.tool_calls || []) {
    output.push({ type: 'function_call', id: 'fc_' + crypto.randomBytes(8).toString('hex'), call_id: tc.id, name: (tc.function && tc.function.name) || '', arguments: (tc.function && tc.function.arguments) || '{}', status: 'completed' });
  }
  return buildResponseObj('resp_' + crypto.randomBytes(12).toString('hex'), clientModel, 'completed', output,
    { input_tokens: (oai.usage && oai.usage.prompt_tokens) || 0, output_tokens: (oai.usage && oai.usage.completion_tokens) || 0 });
}
async function responsesStream(res, up, clientModel) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  const respId = 'resp_' + crypto.randomBytes(12).toString('hex');
  const send = (ev, data) => { try { sseWrite(res, ev, data); } catch {} };
  send('response.created', { type: 'response.created', response: buildResponseObj(respId, clientModel, 'in_progress', [], null) });
  // 状态机:上游 text / tool_calls 增量 -> Responses 事件;任意时刻最多一个 item 开着
  let openIdx = -1, openKind = null; // 'message' | 'function_call'
  let textBuf = '', textItemId = '';
  const tcMap = new Map(); // openai tool_calls index -> {outputIndex, itemId, callId, name, args}
  let outTokens = 0, inTokens = 0;
  const doneItems = [];
  const closeMessage = () => {
    if (openKind !== 'message') return;
    send('response.output_text.done', { type: 'response.output_text.done', output_index: openIdx, content_index: 0, text: textBuf });
    send('response.content_part.done', { type: 'response.content_part.done', output_index: openIdx, content_index: 0, part: { type: 'output_text', text: textBuf, annotations: [] } });
    const item = { type: 'message', id: textItemId, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: textBuf, annotations: [] }] };
    send('response.output_item.done', { type: 'response.output_item.done', output_index: openIdx, item });
    doneItems.push(item);
    openKind = null;
  };
  const closeCall = (e) => {
    send('response.function_call_arguments.done', { type: 'response.function_call_arguments.done', output_index: e.outputIndex, arguments: e.args });
    const item = { type: 'function_call', id: e.itemId, call_id: e.callId, name: e.name, arguments: e.args, status: 'completed' };
    send('response.output_item.done', { type: 'response.output_item.done', output_index: e.outputIndex, item });
    doneItems.push(item);
    e.closed = true;
  };
  let lastChunk = Date.now(), finished = false;
  const pingTimer = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000); // SSE 注释保活
  const idleTimer = setInterval(() => {
    if (!finished && Date.now() - lastChunk > 150000) {
      log('upstream stream idle >150s, closing');
      send('response.failed', { type: 'response.failed', response: buildResponseObj(respId, clientModel, 'failed', doneItems, null) });
      try { res.end(); } catch {}
      try { up.body.destroy(); } catch {}
    }
  }, 5000);
  try {
    const decoder = new TextDecoder();
    let buf = '', done = false;
    for await (const chunk of up.body) {
      lastChunk = Date.now();
      buf += decoder.decode(chunk, { stream: true });
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (data === '[DONE]') { done = true; break; }
        let j; try { j = JSON.parse(data); } catch { continue; }
        const ch = (j.choices && j.choices[0]) || {};
        const delta = ch.delta || {};
        if (delta.content) {
          if (openKind !== 'message') {
            for (const e of tcMap.values()) if (!e.closed) closeCall(e);
            openIdx++; openKind = 'message'; textBuf = ''; textItemId = 'msg_' + crypto.randomBytes(8).toString('hex');
            send('response.output_item.added', { type: 'response.output_item.added', output_index: openIdx, item: { type: 'message', id: textItemId, role: 'assistant', status: 'in_progress', content: [] } });
            send('response.content_part.added', { type: 'response.content_part.added', output_index: openIdx, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
          }
          textBuf += delta.content;
          send('response.output_text.delta', { type: 'response.output_text.delta', output_index: openIdx, content_index: 0, delta: delta.content });
        }
        for (const tc of delta.tool_calls || []) {
          const ti = tc.index != null ? tc.index : 0;
          let entry = tcMap.get(ti);
          if (!entry) {
            closeMessage();
            openIdx++;
            entry = { outputIndex: openIdx, itemId: 'fc_' + crypto.randomBytes(8).toString('hex'), callId: tc.id || ('call_' + crypto.randomBytes(8).toString('hex')), name: (tc.function && tc.function.name) || '', args: '', closed: false };
            tcMap.set(ti, entry);
            openKind = 'function_call';
            send('response.output_item.added', { type: 'response.output_item.added', output_index: openIdx, item: { type: 'function_call', id: entry.itemId, call_id: entry.callId, name: entry.name, arguments: '', status: 'in_progress' } });
          }
          if (tc.id) entry.callId = tc.id;
          if (tc.function && tc.function.name) entry.name = tc.function.name;
          if (tc.function && tc.function.arguments) {
            entry.args += tc.function.arguments;
            send('response.function_call_arguments.delta', { type: 'response.function_call_arguments.delta', output_index: entry.outputIndex, delta: tc.function.arguments });
          }
        }
        if (j.usage) { inTokens = j.usage.prompt_tokens || inTokens; outTokens = j.usage.completion_tokens || outTokens; }
      }
      if (done) break;
    }
  } catch (e) { log('stream error: ' + e.message); }
  finished = true;
  clearInterval(pingTimer); clearInterval(idleTimer);
  closeMessage();
  for (const e of tcMap.values()) if (!e.closed) closeCall(e);
  send('response.completed', { type: 'response.completed', response: buildResponseObj(respId, clientModel, 'completed', doneItems, { input_tokens: inTokens, output_tokens: outTokens }) });
  try { res.end(); } catch {}
}

function roughCountTokens(body) {
  let chars = 0;
  if (body.system) chars += typeof body.system === 'string' ? body.system.length : JSON.stringify(body.system).length;
  if (body.tools) chars += JSON.stringify(body.tools).length;
  for (const m of body.messages || []) chars += typeof m.content === 'string' ? m.content.length : JSON.stringify(m.content || '').length;
  return { input_tokens: Math.max(1, Math.ceil(chars / 3)) };
}
// Anthropic 错误类型映射(/v1/messages 返回 {type:'error',error:{type,message}} 客户端才可识别)
function anthErrType(status) {
  return status === 429 ? 'rate_limit_error' : status === 401 || status === 403 ? 'authentication_error' : status === 400 ? 'invalid_request_error' : 'api_error';
}
function readBody(req, res, cb) {
  let body = '';
  req.on('data', c => { body += c; if (body.length > 50e6) req.destroy(); }); // 50MB:base64 图片场景放宽
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
    res.end(JSON.stringify({ object: 'list', data: [...MODEL_ALIASES, ...IMAGE_MODELS].map(id => ({ id, object: 'model', created: 1700000000, owned_by: 'xiaomi-mimo-relay' })) }));
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
  if (req.method === 'POST' && url === '/v1/images/generations') {
    readBody(req, res, async payload => {
      // OpenAI images API 兼容透传:model 名单外静默回落 Seedream(同 chat 的 resolveModel 哲学),
      // 其余字段(prompt/size/n/response_format 等)原样上行。桌面端同款请求需带 X-Mimo-Source。
      const body = { ...(payload || {}), model: resolveImageModel(payload && payload.model) };
      try {
        const up = await upstream(body, false, UPSTREAM_IMAGES, { 'X-Mimo-Source': 'mimocode-desktop' });
        if (up.ok) {
          // 出图耗时实测 ~37s,b64_json 模式 body 可达数 MB:600s race 超时
          const j = await Promise.race([up.json(), new Promise((_, rej) => setTimeout(() => rej(new Error('upstream body timeout (600s)')), 600000))]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(j));
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
  if (req.method === 'POST' && url === '/v1/responses') {
    readBody(req, res, async payload => {
      const clientModel = typeof payload.model === 'string' ? payload.model : REAL_MODEL;
      const oaiPayload = responsesToOpenAI(payload);
      try {
        const up = await upstream(oaiPayload);
        if (up.ok && oaiPayload.stream) { await responsesStream(res, up, clientModel); return; }
        if (up.ok) {
          const oai = await Promise.race([up.json(), new Promise((_, rej) => setTimeout(() => rej(new Error('upstream body timeout (600s)')), 600000))]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(openAIToResponses(oai, clientModel)));
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
  if (req.method === 'POST' && (url === '/v1/messages' || url === '/v1/chat/completions')) {
    readBody(req, res, async payload => {
      const isAnthropic = url === '/v1/messages';
      const clientModel = typeof payload.model === 'string' ? payload.model : REAL_MODEL;
      const oaiPayload = isAnthropic ? anthropicToOpenAI(payload) : { ...payload, model: resolveModel(payload.model) };
      try {
        const up = await upstream(oaiPayload);
        if (isAnthropic && up.ok && oaiPayload.stream) { await anthropicStream(res, up, clientModel); return; }
        if (isAnthropic && up.ok) {
          const oai = await Promise.race([up.json(), new Promise((_, rej) => setTimeout(() => rej(new Error('upstream body timeout (600s)')), 600000))]);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(openAIToAnthropic(oai, clientModel)));
          return;
        }
        if (isAnthropic) {
          // 上游非 2xx:翻译为 Anthropic 错误格式(Claude Code 只认 {type:'error',error:{type,message}})
          const t = await up.text().catch(() => '');
          let emsg = t.slice(0, 500);
          try { const ej = JSON.parse(t); emsg = (ej.error && (ej.error.message || ej.error)) || ej.message || emsg; } catch {}
          res.writeHead(up.status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: anthErrType(up.status), message: `upstream ${up.status}: ${emsg}` } }));
          return;
        }
        res.writeHead(up.status, { 'Content-Type': up.headers.get('content-type') || 'application/json' });
        if (up.body) { for await (const chunk of up.body) res.write(chunk); }
        res.end();
      } catch (e) {
        const emsg = String((e && e.message) || e);
        if (isAnthropic) {
          if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: emsg } }));
          return;
        }
        if (!res.headersSent) res.writeHead(502);
        res.end(JSON.stringify({ error: emsg }));
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
