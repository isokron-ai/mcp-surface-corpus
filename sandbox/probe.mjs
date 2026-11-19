#!/usr/bin/env node
/**
 * The live surface probe. Talks MCP to one server and records everything it says, then stops it.
 * It sends initialize, notifications/initialized, tools/list (every page), prompts/list,
 * resources/list and resources/templates/list (every page each), and nothing else: no tool is ever
 * called, no prompt fetched, no resource read.
 *
 *   node probe.mjs stdio <time limit ms> <protocol version> -- <command...>
 *   node probe.mjs http  <time limit ms> <protocol version> <url>
 *
 * In the corpus, stdio runs on the runner and <command> is a `docker run -i` of the target's
 * sandbox container (the server never runs on the runner); http runs inside a probe container on
 * the target's --internal network. Prints one JSON object (format isokron-surface-probe/1) on stdout.
 * The server's output is untrusted: every line is kept raw in the transcript (bounded), and parsed
 * results are kept only when they are JSON objects.
 */
import { spawn } from 'node:child_process';

export const FORMAT = 'isokron-surface-probe/1';
export const READ_CAP = 24 * 1024 * 1024;      // bytes of server output read at most
export const LINE_CAP = 4 * 1024 * 1024;       // one transcript line kept at most (longer: cut, flagged)
export const STDERR_CAP = 4 * 1024 * 1024;
export const MAX_PAGES = 100;
export const LIST_METHODS = [
  ['tools/list', 'tools'],
  ['prompts/list', 'prompts'],
  ['resources/list', 'resources'],
  ['resources/templates/list', 'resourceTemplates'],
];
const CLIENT = { name: 'isokron-surface-corpus', version: '1' };
export const PROTOCOL_OFFERED = '2025-11-25';
export const PROTOCOL_MODERN = '2026-07-28';

function newOut(mode, protocol) {
  return {
    format: FORMAT, mode, protocol_offered: protocol, era: null,
    started_at: new Date().toISOString(), captured_at: null,
    timing: { first_byte_ms: null, initialize_ms: null, tools_ms: null, total_ms: null },
    initialize: null, initialize_error: null,
    lists: {}, // method -> { ok, items, pages, page_sizes, first_page_extra, error, error_code, ms }
    transcript: [], transcript_bytes: 0, transcript_truncated: false,
    stderr: '', stderr_bytes: 0, stderr_truncated: false,
    transport: { stdout_bytes: 0, non_json_lines: 0, notifications: [], server_requests: [], exit: null, signal: null, over_cap: false, http: [] },
    error: null,
  };
}

function record(out, t0, dir, raw) {
  const s = typeof raw === 'string' ? raw : String(raw);
  const bytes = Buffer.byteLength(s);
  if (out.transcript_bytes + bytes > READ_CAP) { out.transcript_truncated = true; return; }
  const cut = bytes > LINE_CAP;
  out.transcript.push({ t: Date.now() - t0, dir, bytes, raw: cut ? s.slice(0, LINE_CAP) : s, ...(cut ? { cut: true } : {}) });
  out.transcript_bytes += bytes;
}

function errText(e) {
  return JSON.stringify(e).slice(0, 2000);
}

/** The MCP session over any transport: `rpc(method, params)` resolves { result } or { error, code }. */
async function session(out, rpc, notify, t0, deadline) {
  const timeLeft = () => deadline - Date.now();
  const init = await rpc('initialize', { protocolVersion: out.protocol_offered, capabilities: {}, clientInfo: CLIENT });
  out.timing.initialize_ms = Date.now() - t0;
  // Two eras, as in @isokron/mcp-check's capture: "legacy" servers answer initialize; a server of the
  // stateless 2026-07-28 revision may refuse it and answer the list requests directly when each one
  // carries the protocol version and client info in _meta. A transport that died is not retried.
  let modernMeta = null;
  if (init.error) {
    out.initialize_error = init.error; out.initialize_error_code = init.code ?? null;
    if (init.transport) return;
    out.era = 'modern';
    modernMeta = { 'io.modelcontextprotocol/protocolVersion': PROTOCOL_MODERN, 'io.modelcontextprotocol/clientInfo': CLIENT, 'io.modelcontextprotocol/clientCapabilities': {} };
  } else {
    out.era = 'legacy';
    out.initialize = init.result;
    await notify('notifications/initialized');
  }
  for (const [method, key] of LIST_METHODS) {
    const L = { ok: false, items: null, pages: 0, page_sizes: [], first_page_extra: null, cursors: [], error: null, error_code: null, ms: null };
    out.lists[method] = L;
    const s = Date.now();
    if (timeLeft() <= 0) { L.error = 'time limit'; continue; }
    const items = [];
    let cursor;
    for (;;) {
      const params = { ...(cursor === undefined ? {} : { cursor }), ...(modernMeta ? { _meta: modernMeta } : {}) };
      const page = await rpc(method, Object.keys(params).length ? params : undefined);
      if (page.error) {
        L.error = page.error; L.error_code = page.code ?? null;
        // A modern-era attempt whose first request also fails is a server that did not start: stop asking.
        if (modernMeta && method === 'tools/list' && L.pages === 0) { L.items = []; L.ms = Date.now() - s; out.timing.tools_ms = Date.now() - t0; return; }
        break;
      }
      L.pages++;
      if (method === 'tools/list') (L.raw_pages ||= []).push(page.msg || { jsonrpc: '2.0', result: page.result });
      const arr = page.result[key];
      if (!Array.isArray(arr)) { L.error = `the ${method} result has no ${key} array`; break; }
      items.push(...arr);
      L.page_sizes.push(arr.length);
      if (L.pages === 1) { const { [key]: _x, nextCursor: _n, ...rest } = page.result; L.first_page_extra = Object.keys(rest).length ? rest : null; }
      const next = page.result.nextCursor;
      if (next === undefined || next === null) { L.ok = true; break; }
      if (typeof next !== 'string') { L.error = 'nextCursor is not a string'; break; }
      L.cursors.push(next.slice(0, 256));
      if (L.pages >= MAX_PAGES) { L.error = `paging stopped after ${MAX_PAGES} pages`; break; }
      if (cursor === next) { L.error = 'the server repeated the same cursor'; break; }
      cursor = next;
    }
    L.items = items;
    L.ms = Date.now() - s;
    if (method === 'tools/list') out.timing.tools_ms = Date.now() - t0;
  }
}

function handleMessage(out, m, pending, reply) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) { out.transport.non_json_lines++; return; }
  if (typeof m.method === 'string') {
    if (m.id === undefined) { if (out.transport.notifications.length < 200) out.transport.notifications.push(m.method.slice(0, 128)); return; }
    if (out.transport.server_requests.length < 200) out.transport.server_requests.push(m.method.slice(0, 128));
    if (m.method === 'ping') reply({ jsonrpc: '2.0', id: m.id, result: {} });
    else if (m.method === 'roots/list') reply({ jsonrpc: '2.0', id: m.id, result: { roots: [] } });
    else reply({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
    return;
  }
  const res = pending.get(m.id);
  if (!res) return;
  pending.delete(m.id);
  if (m.error !== undefined) res({ error: errText(m.error), code: m.error && typeof m.error.code === 'number' ? m.error.code : null });
  else if (m.result && typeof m.result === 'object' && !Array.isArray(m.result)) res({ result: m.result, msg: m });
  else res({ error: 'the answer has no result object' });
}

export function probeStdio(command, { protocol, timeoutMs, env = process.env, onSpawn } = {}) {
  return new Promise((done) => {
    const out = newOut('stdio', protocol);
    const t0 = Date.now();
    const deadline = t0 + timeoutMs;
    let child;
    try {
      child = spawn(command[0], command.slice(1), { stdio: ['pipe', 'pipe', 'pipe'], env });
    } catch (e) {
      out.error = `the server did not start: ${e.message}`;
      out.captured_at = new Date().toISOString();
      return done(out);
    }
    if (onSpawn) onSpawn(child);
    const pending = new Map();
    let nextId = 0;
    let closed = null;
    let finished = false;
    let buf = Buffer.alloc(0);
    const send = (m) => {
      const line = JSON.stringify(m);
      record(out, t0, 'c2s', line);
      try { child.stdin.write(`${line}\n`); } catch { /* closed */ }
    };
    const rpc = (method, params) => new Promise((res) => {
      if (closed) return res({ error: closed, transport: true });
      const id = ++nextId;
      pending.set(id, res);
      send({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
    });
    const notify = async (method) => send({ jsonrpc: '2.0', method });
    const failAll = (why) => { closed ??= why; for (const [id, res] of pending) { pending.delete(id); res({ error: why, transport: true }); } };
    child.stdin.on('error', () => {});
    child.stderr.on('data', (c) => {
      out.stderr_bytes += c.length;
      if (out.stderr.length < STDERR_CAP) out.stderr += c.toString('utf8').slice(0, STDERR_CAP - out.stderr.length);
      else out.stderr_truncated = true;
    });
    child.on('error', (e) => failAll(`the server did not start: ${e.message}`));
    child.on('close', (code, signal) => {
      out.transport.exit = code;
      out.transport.signal = signal;
      failAll(`the server exited (exit ${code}, signal ${signal})`);
    });
    child.stdout.on('data', (c) => {
      if (out.timing.first_byte_ms === null) out.timing.first_byte_ms = Date.now() - t0;
      out.transport.stdout_bytes += c.length;
      if (out.transport.stdout_bytes > READ_CAP) {
        if (!out.transport.over_cap) { out.transport.over_cap = true; failAll(`the server wrote more than ${READ_CAP} bytes`); }
        return;
      }
      buf = Buffer.concat([buf, c]);
      let i;
      while ((i = buf.indexOf(10)) >= 0) {
        const line = buf.subarray(0, i).toString('utf8').replace(/\r$/, '');
        buf = buf.subarray(i + 1);
        if (!line.trim()) continue;
        record(out, t0, 's2c', line);
        let m;
        try { m = JSON.parse(line); } catch { out.transport.non_json_lines++; continue; }
        handleMessage(out, m, pending, (r) => send(r));
      }
    });
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      out.captured_at = new Date().toISOString();
      out.timing.total_ms = Date.now() - t0;
      try { child.stdin.end(); } catch { /* closed */ }
      const kill = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 3000);
      kill.unref();
      if (out.transport.exit === null) {
        child.once('close', () => { clearTimeout(kill); done(out); });
        try { child.kill('SIGTERM'); } catch { /* gone */ }
      } else done(out);
    };
    const timer = setTimeout(() => { if (!out.error) out.error = `time limit (${timeoutMs} ms)`; failAll(`time limit (${timeoutMs} ms)`); }, timeoutMs);
    session(out, rpc, notify, t0, deadline).then(finish, (e) => { out.error = `probe error: ${e.message}`; finish(); });
  });
}

/** Streamable HTTP (MCP 2025-03-26 and later): POST each message; the answer is JSON or an SSE stream. */
export async function probeHttp(url, { protocol, timeoutMs, readyMs } = {}) {
  const out = newOut('http', protocol);
  out.url = url;
  const t0 = Date.now();
  const deadline = t0 + timeoutMs;
  let sessionId = null;
  let negotiated = null;
  let nextId = 0;
  let readBytes = 0;
  // Wait for the port: retry connection errors until readyMs (default: half the limit).
  const readyBy = t0 + (readyMs ?? Math.floor(timeoutMs / 2));
  const post = async (body, isNote) => {
    const line = JSON.stringify(body);
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) return { error: `time limit (${timeoutMs} ms)`, transport: true };
      const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
      if (sessionId) headers['mcp-session-id'] = sessionId;
      if (negotiated) headers['mcp-protocol-version'] = negotiated;
      let r;
      try {
        r = await fetch(url, { method: 'POST', headers, body: line, signal: AbortSignal.timeout(left), redirect: 'manual' });
      } catch (e) {
        const code = e.cause && e.cause.code;
        if ((code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'ECONNRESET') && Date.now() < readyBy && !out.initialize) {
          await new Promise((r2) => setTimeout(r2, 250));
          continue;
        }
        return { error: `HTTP request failed: ${code || e.name}: ${String(e.message).slice(0, 300)}`, transport: true };
      }
      record(out, t0, 'c2s', line);
      if (out.timing.first_byte_ms === null) out.timing.first_byte_ms = Date.now() - t0;
      const sid = r.headers.get('mcp-session-id');
      if (sid && !sessionId) sessionId = sid.slice(0, 512);
      const ctype = (r.headers.get('content-type') || '').toLowerCase();
      const text = await r.text();
      readBytes += Buffer.byteLength(text);
      out.transport.http.push({ status: r.status, content_type: ctype.slice(0, 128), bytes: Buffer.byteLength(text), session: !!sid });
      record(out, t0, 's2c', text);
      if (readBytes > READ_CAP) { out.transport.over_cap = true; return { error: `the server wrote more than ${READ_CAP} bytes` }; }
      if (isNote) return { result: {} };
      if (r.status >= 400) return { error: `HTTP ${r.status}: ${text.slice(0, 500)}`, code: r.status };
      const msgs = [];
      if (ctype.includes('text/event-stream')) {
        for (const ev of text.split(/\r?\n\r?\n/)) {
          const data = ev.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
          if (!data) continue;
          try { msgs.push(JSON.parse(data)); } catch { out.transport.non_json_lines++; }
        }
      } else {
        try { const j = JSON.parse(text); if (Array.isArray(j)) msgs.push(...j); else msgs.push(j); } catch { out.transport.non_json_lines++; }
      }
      const pending = new Map();
      let got = null;
      pending.set(body.id, (x) => { got = x; });
      for (const m of msgs) handleMessage(out, m, pending, () => { /* no server->client channel on POST */ });
      return got || { error: 'no JSON-RPC answer to the request' };
    }
  };
  const rpc = async (method, params) => {
    const r = await post({ jsonrpc: '2.0', id: ++nextId, method, ...(params === undefined ? {} : { params }) });
    if (method === 'initialize' && r.result && typeof r.result.protocolVersion === 'string') negotiated = r.result.protocolVersion.slice(0, 32);
    return r;
  };
  const notify = (method) => post({ jsonrpc: '2.0', method }, true);
  try {
    await session(out, rpc, notify, t0, deadline);
  } catch (e) {
    out.error = `probe error: ${e.message}`;
  }
  if (sessionId) {
    try { await fetch(url, { method: 'DELETE', headers: { 'mcp-session-id': sessionId }, signal: AbortSignal.timeout(2000) }); } catch { /* best effort */ }
  }
  out.captured_at = new Date().toISOString();
  out.timing.total_ms = Date.now() - t0;
  return out;
}

/** True when the probe got a whole tools/list (every page). */
export const listed = (out) => !!(out && out.lists && out.lists['tools/list'] && out.lists['tools/list'].ok);

if (import.meta.url === `file://${process.argv[1]}`) {
  const [mode, ms, protocol, ...rest] = process.argv.slice(2);
  const usage = () => { process.stderr.write('usage: probe.mjs stdio <ms> <protocol> -- <command...> | probe.mjs http <ms> <protocol> <url>\n'); process.exit(2); };
  if (!(Number(ms) > 0) || !protocol) usage();
  let out;
  if (mode === 'stdio') {
    if (rest[0] !== '--' || rest.length < 2) usage();
    out = await probeStdio(rest.slice(1), { protocol, timeoutMs: Number(ms) });
  } else if (mode === 'http') {
    if (!/^https?:\/\//.test(rest[0] || '')) usage();
    out = await probeHttp(rest[0], { protocol, timeoutMs: Number(ms) });
  } else usage();
  process.stdout.write(`${JSON.stringify(out)}\n`, () => process.exit(listed(out) ? 0 : 1));
}
