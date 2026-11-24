// Evidence folders as actions/download-artifact leaves them (one folder per artifact), for the
// checks that recompute a conformance verdict from telemetry alone (scripts/verify-conformance.mjs).
// The records are those of test/check-selftest.test.mjs and test/mutation.test.mjs.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Telemetry } from '../src/telemetry.mjs';
import { CASES } from '../src/selftest.mjs';
import { EXPECT } from '../scripts/check-mutation.mjs';
import { GOOD } from './selftest-fixtures.mjs';

const hex = (c) => c.repeat(64);

/** A self test run with the evidence of a working sandbox for every case; `bad` names a case that got through. */
export function selftestTelemetry(file, { bad = null, end = '2026-11-20T03:58:12.345Z' } = {}) {
  const tel = new Telemetry(file, { run: '20261124t034000-000001', clock: () => new Date(end) });
  tel.write('run_start', { kind: 'selftest', lane: 'ci', node: 'v22.0.0', platform: 'linux/x64', runtime: 'runsc', gvisor_release: '20261116.0' });
  tel.write('runtime', { available: true, name: 'runsc', release: '20261116.0', flags_expected: [], flags_daemon: [], flags_match: true, smoke: 'ok' });
  tel.write('firewall', { live: true, problems: [] });
  for (const name of CASES) {
    const meta = { subject: `case:${name}`, role: 'case' };
    const ev = GOOD[name]();
    if (name === bad) ev.inspect.mismatches = ['the root filesystem is not read-only'];
    tel.write('settings', { digest: hex('a'), manifest: { runtime: 'runsc' } }, meta);
    tel.write('container', { runtime: 'runsc', exit: 0, signal: null, timed_out: false, oom_killed: false, ms: 10 }, meta);
    tel.write('target_output', { stream: 'stdout', bytes: ev.output.bytes, sha256: hex('b'), untrusted: true }, meta);
    for (const d of ev.dns) tel.write('dns_query', { from: d.from ?? null, proto: d.proto, qname: d.qname, qtype: d.qtype, answer: d.answer }, { ...meta, source: 'netlog' });
    for (const c of ev.conns) tel.write('connection', { ...c, from: c.from ?? null }, { ...meta, source: 'netlog' });
    for (const d of ev.drops) tel.write('host_drop', d, { ...meta, source: 'host' });
    for (const e of ev.egress ?? []) tel.write('egress', e, { ...meta, source: 'proxy' });
    if (ev.trace) tel.write('trace_summary', { summary: ev.trace }, { source: 'runsc', ...meta });
    tel.write('case_evidence', { case: name, limits_hit: [], canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches, canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: 512 }, meta);
    tel.write('bypass_result', { case: name, blocked: true, logged: true, pass: true, evidence: ['trace: x'], detail: 'ok' }, meta);
  }
  tel.end(true);
}

/** A protection-off run that failed for the reason that protection explains. */
export function mutationTelemetry(file, protection) {
  const tel = new Telemetry(file, { run: '20261124t034000-000002' });
  tel.write('run_start', { kind: 'selftest', lane: 'selftest-mutation', node: 'v22', platform: 'linux/x64', runtime: 'runsc', gvisor_release: '20261116.0', disabled: protection });
  const exp = EXPECT[protection];
  if (exp.preflight) {
    const detail = {
      'firewall-forward': 'the firewall is not the one net-guard.sh makes: iptables ISK-SBX is not the chain net-guard.sh makes (0 rules; rule 1: missing)',
      'firewall-input': 'the firewall is not the one net-guard.sh makes: iptables INPUT lacks: -A INPUT -i br-+ -j ISK-SBX-IN',
      'firewall-order': 'the firewall is not the one net-guard.sh makes: iptables DOCKER-USER: -A DOCKER-USER -s 10.213.52.0/22 -j ISK-SBX comes after -A DOCKER-USER -s 10.213.52.0/22 -j ACCEPT',
      'firewall-order-goto': 'the firewall is not the one net-guard.sh makes: iptables DOCKER-USER: -A DOCKER-USER -d 10.213.52.0/22 -j ISK-SBX comes after -A DOCKER-USER -s 10.213.52.0/22 -g ISK-MUT-GOTO',
    }[protection];
    tel.write('skip', { reason: 'sandbox_setup_missing', detail });
  } else {
    const ev = GOOD[exp.case]();
    let evidence = [];
    if (protection === 'runtime-runc') { ev.inspect.runtime = 'runc'; ev.trace = null; }
    if (protection === 'cap-drop') { ev.inspect.mismatches = ['capabilities are not all dropped']; evidence = ['target: CapEff 0000000000000000 CapBnd 00000000a80425fb']; }
    if (protection === 'env-filter') ev.inspect.canaryInEnv = true;
    if (protection === 'read-only') ev.trace.opens_outside[0] = { path: '/var/tmp/isk-1', op: 'write', call: 'openat', n: 1, failed: 0, errno: null };
    if (protection === 'internal-net') for (const c of ev.trace.network.connects) c.errno = 4;
    if (protection === 'proxy-allowlist') ev.egress = [...ev.egress.filter((e) => e.host !== 'example.com' || e.port !== 443), { host: 'example.com', port: 443, allowed: true, up: 0, down: 0, ms: 3, error: 'EAI_AGAIN' }];
    const meta = { subject: `case:${exp.case}`, role: 'case' };
    tel.write('container', { runtime: ev.inspect.runtime, exit: 0, signal: null, timed_out: false, oom_killed: false, ms: 1 }, meta);
    tel.write('target_output', { stream: 'stdout', bytes: 10, sha256: hex('b'), untrusted: true }, meta);
    if (ev.trace) tel.write('trace_summary', { summary: ev.trace }, { ...meta, source: 'runsc' });
    for (const d of ev.dns) tel.write('dns_query', d, { ...meta, source: 'netlog' });
    for (const x of ev.conns) tel.write('connection', x, { ...meta, source: 'netlog' });
    for (const d of ev.drops) tel.write('host_drop', d, { ...meta, source: 'host' });
    for (const e of ev.egress ?? []) tel.write('egress', e, { ...meta, source: 'proxy' });
    tel.write('case_evidence', { case: exp.case, limits_hit: [], canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches, canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: 512 }, meta);
    tel.write('bypass_result', { case: exp.case, blocked: false, logged: false, pass: false, evidence, detail: 'x' }, meta);
  }
  tel.end(false);
}

/**
 * An evidence folder for PREFIX: the self test (bad: a case that got through), every mutation
 * shown, minus the artifacts named in `missing`; `passing` names mutations that wrongly passed.
 */
export function evidenceDir(prefix, { bad = null, missing = [], passing = [], end } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'evidence-'));
  if (!missing.includes('selftest')) {
    mkdirSync(join(dir, `${prefix}-selftest`));
    selftestTelemetry(join(dir, `${prefix}-selftest`, 'telemetry.jsonl'), { bad, end });
    writeFileSync(join(dir, `${prefix}-selftest`, 'environment.json'), JSON.stringify({ runner_image: 'ubuntu24/20261117.1', kernel: '6.11.0-1018-azure', docker: '28.0.4', gvisor_release: '20261116.0', runsc_version: 'release-20261116.0' }));
  }
  for (const p of Object.keys(EXPECT)) {
    if (missing.includes(p)) continue;
    mkdirSync(join(dir, `${prefix}-mutation-${p}`));
    const f = join(dir, `${prefix}-mutation-${p}`, 'telemetry.jsonl');
    if (passing.includes(p)) selftestTelemetry(f);
    else mutationTelemetry(f, p);
  }
  return dir;
}
