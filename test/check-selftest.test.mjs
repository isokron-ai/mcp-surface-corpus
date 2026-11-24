import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Telemetry } from '../src/telemetry.mjs';
import { CASES } from '../src/selftest.mjs';
import { GOOD } from './selftest-fixtures.mjs';
import { checkSelftest } from '../scripts/check-selftest.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const fixed = () => new Date('2026-11-21T10:00:00.000Z');
const hex = (c) => c.repeat(64);

/**
 * A synthetic self test run with the evidence of a working sandbox for every case (the same fixtures
 * as test/selftest.test.mjs), unless `tweak` changes a case: `blocked: false` makes the evidence show
 * a container with other settings, `logged: false` drops its trace, `runtime` changes its container
 * record, `harness` sets the harness's own verdict apart from the evidence.
 */
function telemetry({ cases = CASES, tweak = {}, skip = false, endOk = true, omit = [], dropped = 0, firewall = true } = {}) {
  const f = join(mkdtempSync(join(tmpdir(), 'chk-')), 'telemetry.jsonl');
  const tel = new Telemetry(f, { run: '20261121t100000-000001', clock: fixed });
  tel.write('run_start', { kind: 'selftest', lane: 'ci', node: 'v22.0.0', platform: 'linux/x64', runtime: 'runsc', gvisor_release: '20261116.0' });
  tel.write('runtime', { available: true, name: 'runsc', release: '20261116.0', flags_expected: [], flags_daemon: [], flags_match: true, smoke: 'ok' });
  if (firewall !== null) tel.write('firewall', { live: firewall, problems: firewall ? [] : ['iptables INPUT lacks: -A INPUT -i br-+ -j ISK-SBX-IN'] });
  if (skip) tel.write('skip', { reason: 'trace_unavailable', detail: 'no trace' });
  for (const name of cases) {
    const meta = { subject: `case:${name}`, role: 'case' };
    const t = tweak[name] || {};
    const ev = GOOD[name]();
    if (t.blocked === false) ev.inspect.mismatches = ['the root filesystem is not read-only'];
    if (t.logged === false) ev.trace = null;
    if (!omit.includes(`${name}:settings`)) tel.write('settings', { digest: hex('a'), manifest: { runtime: 'runsc' } }, meta);
    if (!omit.includes(`${name}:container`)) tel.write('container', { runtime: t.runtime ?? 'runsc', exit: 0, signal: null, timed_out: false, oom_killed: false, ms: 10 }, meta);
    tel.write('target_output', { stream: 'stdout', bytes: ev.output.bytes, sha256: hex('b'), untrusted: true }, meta);
    for (const d of ev.dns) tel.write('dns_query', { from: d.from ?? null, proto: d.proto, qname: d.qname, qtype: d.qtype, answer: d.answer }, { ...meta, source: 'netlog' });
    for (const c of ev.conns) tel.write('connection', { ...c, from: c.from ?? null }, { ...meta, source: 'netlog' });
    for (const d of ev.drops) tel.write('host_drop', d, { ...meta, source: 'host' });
    for (const e of ev.egress ?? []) tel.write('egress', e, { ...meta, source: 'proxy' });
    if (!omit.includes(`${name}:trace`) && ev.trace) tel.write('trace_summary', { summary: ev.trace }, { source: 'runsc', ...meta });
    if (!omit.includes(`${name}:evidence`)) tel.write('case_evidence', { case: name, limits_hit: t.limits ?? [], canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches, canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: 512 }, meta);
    if (!omit.includes(`${name}:result`)) {
      const pass = t.harness ?? ((t.blocked ?? true) && (t.logged ?? true));
      tel.write('bypass_result', { case: name, blocked: pass, logged: pass, pass, evidence: ['trace: x'], detail: 'ok' }, meta);
    }
  }
  tel.dropped = dropped;
  tel.end(endOk);
  return f;
}

test('check-selftest: every case blocked and logged, with its trace, settings and runsc container, passes', () => {
  const r = checkSelftest(telemetry());
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(r.lines.filter((l) => / ok$/.test(l)).length, CASES.length);
});

test('check-selftest: a case that got through, or was not logged, fails the run', () => {
  for (const tw of [{ blocked: false }, { logged: false }]) {
    const r = checkSelftest(telemetry({ tweak: { 'direct-ip': tw } }));
    assert.equal(r.ok, false, JSON.stringify(tw));
    assert.ok(r.lines.some((l) => l.startsWith('direct-ip: FAIL')), r.lines.join('\n'));
  }
});

test('check-selftest: missing evidence in the telemetry is a failure, not a pass', () => {
  for (const o of ['icmp:trace', 'icmp:settings', 'icmp:container', 'icmp:result', 'icmp:evidence']) {
    const r = checkSelftest(telemetry({ omit: [o] }));
    assert.equal(r.ok, false, o);
    assert.ok(r.lines.some((l) => l.startsWith('icmp: FAIL')), `${o}: ${r.lines.join('\n')}`);
  }
  assert.equal(checkSelftest(telemetry({ tweak: { 'fork-bomb': { runtime: 'runc' } } })).ok, false, 'a case container that ran under runc');
  assert.equal(checkSelftest(telemetry({ cases: CASES.slice(1) })).ok, false, 'a case that never ran');
});

test('check-selftest: a skip, a run that did not end well, or a line that is not a record fails', () => {
  assert.equal(checkSelftest(telemetry({ skip: true })).ok, false);
  assert.equal(checkSelftest(telemetry({ endOk: false })).ok, false);
  const f = telemetry();
  appendFileSync(f, '{"type":"bypass_result","case":"icmp","pass":true}\n');
  const r = checkSelftest(f);
  assert.equal(r.ok, false);
  assert.ok(r.lines.some((l) => /not a valid record/.test(l)));
  const dup = telemetry();
  const tel = new Telemetry(dup, { run: '20261121t100000-000001', clock: fixed });
  tel.seq = 999;
  tel.write('bypass_result', { case: 'icmp', blocked: true, logged: true, pass: true, evidence: [], detail: 'again' }, { subject: 'case:icmp', role: 'case' });
  assert.equal(checkSelftest(dup).ok, false, 'two verdicts for one case');
});

test('check-selftest: the command line prints one line per case and exits 1 on any failure', () => {
  const run = (f, extra = []) => spawnSync(process.execPath, [join(root, 'scripts/check-selftest.mjs'), f, ...extra], { encoding: 'utf8' });
  const good = run(telemetry());
  assert.equal(good.status, 0, good.stdout + good.stderr);
  assert.match(good.stdout, new RegExp(`all ${CASES.length} cases blocked and logged`));
  const bad = run(telemetry({ tweak: { metadata: { blocked: false } } }));
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /metadata: FAIL/);
  const some = run(telemetry({ cases: ['icmp', 'ipv6'] }), ['--cases', 'icmp,ipv6']);
  assert.equal(some.status, 0, some.stdout);
  assert.equal(run(join(tmpdir(), 'no-such-file.jsonl')).status, 1);
  writeFileSync(join(tmpdir(), 'chk-empty.jsonl'), '');
  assert.equal(run(join(tmpdir(), 'chk-empty.jsonl')).status, 1);
});

test('R-SBX-01 check-selftest: evidence the schema refused and left out fails the run', () => {
  const r = checkSelftest(telemetry({ dropped: 2 }));
  assert.equal(r.ok, false);
  assert.ok(r.lines.some((l) => /2 record\(s\) of evidence were refused/.test(l)), r.lines.join('\n'));
});

test('R-SBX-08 check-selftest: the verdict comes from the evidence; a harness that says pass cannot make one', () => {
  const r = checkSelftest(telemetry({ tweak: { metadata: { blocked: false, harness: true } } }));
  assert.equal(r.ok, false);
  assert.ok(r.lines.some((l) => /^metadata: FAIL \(not blocked/.test(l)), r.lines.join('\n'));
  const v = checkSelftest(telemetry({ tweak: { icmp: { harness: false } } }));
  assert.equal(v.ok, false, 'a harness verdict that is not a pass still vetoes');
});

test('R-SBX-05 check-selftest: the host firewall must have been checked live at the preflight', () => {
  for (const firewall of [false, null]) {
    const r = checkSelftest(telemetry({ firewall }));
    assert.equal(r.ok, false, String(firewall));
    assert.ok(r.lines.some((l) => /firewall was not checked live/.test(l)), r.lines.join('\n'));
  }
});

test('R-SBX-04 check-selftest: a case whose evidence a log or rate limit cut short fails', () => {
  const r = checkSelftest(telemetry({ tweak: { 'docker-host': { limits: ['firewall ISK-SBX-IN: 4 drop(s) not logged (rate limit)'] } } }));
  assert.equal(r.ok, false);
  assert.ok(r.lines.some((l) => /^docker-host: FAIL .*rate limit/.test(l)), r.lines.join('\n'));
});
