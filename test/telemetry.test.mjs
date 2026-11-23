import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Telemetry, TelemetryError, TYPES, SOURCES, ROLES, SKIP_REASONS, TELEMETRY_VERSION, validateRecord, readTelemetry, fromNetlog, fromProxy, fromDrop, newRunId } from '../src/telemetry.mjs';

const root = new URL('..', import.meta.url).pathname;
const tmp = () => mkdtempSync(join(tmpdir(), 'tel-'));
const fixed = () => new Date('2026-11-21T10:00:00.000Z');

test('records are written one per line, in sequence, each checked against the schema', () => {
  const f = join(tmp(), 't.jsonl');
  const tel = new Telemetry(f, { run: 'run-0001', clock: fixed });
  tel.write('run_start', { kind: 'selftest', lane: 'selftest', node: 'v22.0.0', platform: 'linux-x64', runtime: 'runsc', gvisor_release: '20261116.0' });
  tel.write('skip', { reason: 'runtime_unavailable', detail: 'runsc is not a configured runtime' }, { subject: 'demo', role: 'server' });
  tel.end(false);
  const lines = readFileSync(f, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((r) => [r.seq, r.type]), [[0, 'run_start'], [1, 'skip'], [2, 'run_end']]);
  assert.ok(lines.every((r) => r.v === TELEMETRY_VERSION && r.run === 'run-0001' && r.t === '2026-11-21T10:00:00.000Z'));
  assert.deepEqual([lines[1].subject, lines[1].role, lines[1].source], ['demo', 'server', 'harness']);
  assert.deepEqual([lines[2].records, lines[2].skipped, lines[2].ok], [3, 1, false]);
});

test('a record that does not match the schema is refused, not written', () => {
  const f = join(tmp(), 't.jsonl');
  writeFileSync(f, '');
  const tel = new Telemetry(f, { run: 'run-0001', clock: fixed });
  assert.throws(() => tel.write('nonsense', {}), TelemetryError);
  assert.throws(() => tel.write('skip', { reason: 'because', detail: 'x' }), /skip\.reason/);
  assert.throws(() => tel.write('dns_query', { from: '10.213.53.3', proto: 'udp', qname: 'x', qtype: 'A', answer: 'sinkhole' }, { source: 'target' }), /source/);
  assert.throws(() => tel.write('target_output', { stream: 'stdout', bytes: 3, sha256: 'a'.repeat(64), untrusted: false }), /untrusted/);
  assert.throws(() => tel.write('settings', { digest: 'a'.repeat(64), manifest: {} }, { subject: 'Bad Subject' }), /subject/);
  assert.equal(readFileSync(f, 'utf8'), '');
  assert.equal(tel.seq, 0);
  assert.deepEqual(validateRecord(null), ['not an object']);
});

test('reading telemetry back reports bad lines instead of dropping them', () => {
  const f = join(tmp(), 't.jsonl');
  const tel = new Telemetry(f, { run: 'run-0001', clock: fixed });
  tel.write('egress', { host: 'registry.npmjs.org', port: 443, allowed: true }, { source: 'proxy', subject: 'demo', role: 'install' });
  appendFileSync(f, 'not json\n{"v":1,"type":"egress"}\n');
  const { records, bad } = readTelemetry(f);
  assert.equal(records.length, 1);
  assert.deepEqual(bad.map((b) => b.line), [2, 3]);
  assert.deepEqual(bad[0].errors, ['not JSON']);
});

test('network logger, proxy and firewall lines become records, cut to size', () => {
  const [t1, d] = fromNetlog({ kind: 'dns', t: 'x', from: '10.213.53.3', proto: 'udp', qname: 'a'.repeat(400), qtype: 'AAAA', answer: 'empty' });
  assert.equal(t1, 'dns_query');
  assert.equal(d.qname.length, 253);
  const [t2, c] = fromNetlog({ kind: 'conn', from: '10.213.53.3', proto: 'tcp', port: 443, bytes: 517, sni: 'dns.google', first_hex: 'ab'.repeat(100), http: null });
  assert.equal(t2, 'connection');
  assert.deepEqual([c.port, c.bytes, c.sni, c.first_hex.length, 'http' in c], [443, 517, 'dns.google', 64, false]);
  const [, h] = fromNetlog({ kind: 'conn', from: '10.213.53.3', proto: 'tcp', port: 80, bytes: 40, http: { method: 'GET', host: 'example.com', path: '/x' } });
  assert.deepEqual(h.http, { method: 'GET', host: 'example.com', path: '/x' });
  assert.equal(fromNetlog({ kind: 'listening' }), null);
  assert.equal(fromNetlog('x'), null);
  const [t3, e] = fromProxy({ t: 'x', host: 'evil.example', port: 443, allowed: false, error: 'not allowed', up: 0, down: 0, ms: 1 });
  assert.deepEqual([t3, e.host, e.allowed, e.error, e.ms], ['egress', 'evil.example', false, 'not allowed', 1]);
  assert.equal(fromProxy({ listening: 8080 }), null);
  const [t4, k] = fromDrop({ chain: 'forward', family: 4, proto: 'ICMP', src: '10.213.53.3', dst: '1.1.1.1', dpt: null, icmp_type: 8, n: 3 });
  assert.deepEqual([t4, k.proto, k.icmp_type, k.n], ['host_drop', 'ICMP', 8, 3]);
  const f = join(tmp(), 't.jsonl');
  const tel = new Telemetry(f, { run: newRunId(fixed(), () => 0.5), clock: fixed });
  for (const [type, fields, source] of [[t1, d, 'netlog'], [t2, c, 'netlog'], [t3, e, 'proxy'], [t4, k, 'host']]) tel.write(type, fields, { source, subject: 'case:direct-ip', role: 'case' });
  assert.equal(readTelemetry(f).bad.length, 0);
});

test('run ids are lower case, sortable by time and accepted by the schema', () => {
  const id = newRunId(fixed(), () => 0);
  assert.equal(id, '20261121t100000-000000');
  assert.deepEqual(validateRecord({ v: 1, type: 'run_end', run: id, seq: 0, t: fixed().toISOString(), source: 'harness', subject: null, role: null, records: 1, skipped: 0, ok: true }), []);
});

test('docs/TELEMETRY.md documents every record type, field, source, role and skip reason', () => {
  const doc = readFileSync(join(root, 'docs', 'TELEMETRY.md'), 'utf8');
  for (const f of ['v', 'type', 'run', 'seq', 't', 'source', 'subject', 'role']) assert.match(doc, new RegExp(`\`${f}\``), `envelope field ${f}`);
  for (const [type, fields] of Object.entries(TYPES)) {
    assert.match(doc, new RegExp(`^### \`${type}\``, 'm'), `section for ${type}`);
    const section = doc.split(new RegExp(`^### \`${type}\``, 'm'))[1].split(/^### /m)[0];
    for (const k of Object.keys(fields)) assert.match(section, new RegExp(`\`${k}\``), `${type}.${k}`);
  }
  for (const s of [...SOURCES, ...ROLES, ...SKIP_REASONS]) assert.match(doc, new RegExp(`\`${s}\``), s);
});
