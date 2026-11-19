import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { probeStdio, probeHttp, listed, PROTOCOL_OFFERED, FORMAT } from '../sandbox/probe.mjs';

const NULL = fileURLToPath(new URL('../sandbox/null-server.mjs', import.meta.url));
const stdio = (args, o = {}) => probeStdio([process.execPath, NULL, ...args], { protocol: PROTOCOL_OFFERED, timeoutMs: 10_000, ...o });

test('stdio: initialize, every list, the raw transcript in both directions, and nothing called', async () => {
  const p = await stdio(['--tools', '3']);
  assert.equal(p.format, FORMAT);
  assert.ok(listed(p));
  assert.equal(p.era, 'legacy');
  assert.equal(p.initialize.serverInfo.name, 'null-server');
  assert.equal(p.initialize.protocolVersion, PROTOCOL_OFFERED);
  assert.equal(p.lists['tools/list'].items.length, 3);
  assert.equal(p.lists['tools/list'].raw_pages.length, 1);
  assert.equal(p.lists['prompts/list'].items.length, 1);
  assert.equal(p.lists['resources/list'].ok, false);
  assert.equal(p.lists['resources/list'].error_code, -32601);
  const sent = p.transcript.filter((x) => x.dir === 'c2s').map((x) => JSON.parse(x.raw).method);
  assert.deepEqual(sent, ['initialize', 'notifications/initialized', 'tools/list', 'prompts/list', 'resources/list', 'resources/templates/list']);
  assert.ok(!sent.some((m) => /call|get|read|subscribe|complete/.test(m)), 'only initialize and list methods are ever sent');
  assert.equal(p.transcript.filter((x) => x.dir === 's2c').length, 5);
  assert.ok(p.timing.initialize_ms >= 0 && p.timing.tools_ms >= p.timing.initialize_ms);
});

test('stdio: every page of a paginated list is followed and recorded', async () => {
  const p = await stdio(['--tools', '7', '--page', '3']);
  const L = p.lists['tools/list'];
  assert.deepEqual([L.ok, L.pages, L.items.length], [true, 3, 7]);
  assert.deepEqual(L.page_sizes, [3, 3, 1]);
  assert.equal(L.raw_pages.length, 3);
});

test('stdio: a stateless (2026-07-28) server that refuses initialize is listed with _meta', async () => {
  const p = await stdio(['--modern']);
  assert.ok(listed(p));
  assert.equal(p.era, 'modern');
  assert.equal(p.initialize, null);
  assert.ok(p.initialize_error);
  const req = JSON.parse(p.transcript.filter((x) => x.dir === 'c2s')[1].raw);
  assert.equal(req.params._meta['io.modelcontextprotocol/protocolVersion'], '2026-07-28');
});

test('stdio: stdout noise is counted and kept raw; a server that needs a credential is recorded as not starting', async () => {
  const noisy = await stdio(['--noise']);
  assert.ok(listed(noisy));
  assert.equal(noisy.transport.non_json_lines, 1);
  assert.equal(noisy.transcript.find((x) => x.dir === 's2c').raw, 'null-server starting');
  const need = await stdio(['--need-env', 'SURFACE_TEST_KEY'], { env: { PATH: process.env.PATH } });
  assert.equal(listed(need), false);
  assert.equal(need.era, null);
  assert.match(need.stderr, /SURFACE_TEST_KEY is required/);
  assert.equal(need.transport.exit, 1);
  const withEnv = await stdio(['--need-env', 'SURFACE_TEST_KEY'], { env: { PATH: process.env.PATH, SURFACE_TEST_KEY: 'surface-dummy-not-a-credential' } });
  assert.ok(listed(withEnv));
});

test('stdio: a silent server is stopped at the time limit, with its process gone', async () => {
  let child;
  const p = await probeStdio([process.execPath, '-e', 'setInterval(()=>{}, 1000)'], { protocol: PROTOCOL_OFFERED, timeoutMs: 400, onSpawn: (c) => { child = c; } });
  assert.equal(listed(p), false);
  assert.match(p.error, /time limit/);
  assert.ok(child.killed || child.exitCode !== null || child.signalCode !== null);
});

test('stdio: a command that does not exist is an error in the record, not a crash', async () => {
  const p = await probeStdio(['/nonexistent/server'], { protocol: PROTOCOL_OFFERED, timeoutMs: 2000 });
  assert.equal(listed(p), false);
});

test('http: streamable HTTP with a session header', async () => {
  const child = spawn(process.execPath, [NULL, '--http', '39417', '--tools', '4'], { stdio: 'ignore' });
  try {
    const p = await probeHttp('http://127.0.0.1:39417/mcp', { protocol: PROTOCOL_OFFERED, timeoutMs: 10_000 });
    assert.ok(listed(p));
    assert.equal(p.mode, 'http');
    assert.equal(p.lists['tools/list'].items.length, 4);
    assert.ok(p.transport.http.length >= 5 && p.transport.http[0].session === true);
    assert.equal(p.transcript.filter((x) => x.dir === 'c2s').length, p.transcript.filter((x) => x.dir === 's2c').length);
  } finally { child.kill('SIGKILL'); }
});
