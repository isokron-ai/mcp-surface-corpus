// The protection-off switch of the self test (bin/sandbox-selftest.mjs --disable) and the check that
// a mutated run failed for the reason the protection explains (scripts/check-mutation.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MUTATIONS, mutateCaseArgs, mutateHost, parseArgs } from '../bin/sandbox-selftest.mjs';
import { EXPECT, checkMutation } from '../scripts/check-mutation.mjs';
import { sandboxRunArgs } from '../src/docker.mjs';
import { Telemetry } from '../src/telemetry.mjs';
import { GOOD } from './selftest-fixtures.mjs';

const IMG = `docker.io/library/python:3.13-slim-bookworm@sha256:${'a'.repeat(64)}`;
const caseArgs = () => sandboxRunArgs({ name: 'surface-x-case1', image: IMG, network: 'surface-x-run', detach: true, env: { HOME: '/tmp/home' }, cmd: ['python3', 'h.py'], hostEnv: {} });

test('--disable is refused on every lane but selftest-mutation, and that lane needs one protection it knows', () => {
  assert.throws(() => parseArgs(['--out', 'o', '--disable', 'cap-drop']), /refused except on the selftest-mutation lane/);
  assert.throws(() => parseArgs(['--out', 'o', '--lane', 'ci', '--disable', 'cap-drop']), /refused/);
  assert.throws(() => parseArgs(['--out', 'o', '--lane', 'selftest-mutation']), /needs --disable/);
  assert.throws(() => parseArgs(['--out', 'o', '--lane', 'selftest-mutation', '--disable', 'everything']), /needs --disable with one of/);
  assert.equal(parseArgs(['--out', 'o', '--lane', 'selftest-mutation', '--disable', 'read-only']).disable, 'read-only');
  assert.equal(parseArgs(['--out', 'o', '--lane', 'ci']).disable, null);
});

test('each container mutation takes out exactly its one protection', () => {
  const a = caseArgs();
  const can = { GITHUB_TOKEN: 'isk-canary-1' };
  const diff = (m) => { const b = mutateCaseArgs(a, m, can); return { b, gone: a.filter((x, i) => b[i] !== x).length, len: b.length - a.length }; };
  const r = diff('runtime-runc');
  assert.equal(r.b[r.b.indexOf('--runtime') + 1], 'runc');
  assert.equal(r.len, 0);
  assert.ok(!mutateCaseArgs(a, 'cap-drop', can).join(' ').includes('--cap-drop ALL'));
  assert.equal(diff('cap-drop').len, -2);
  assert.ok(!mutateCaseArgs(a, 'read-only', can).includes('--read-only'));
  assert.equal(diff('read-only').len, -1);
  const e = mutateCaseArgs(a, 'env-filter', can);
  assert.ok(e.includes('GITHUB_TOKEN=isk-canary-1'));
  assert.ok(e.indexOf('GITHUB_TOKEN=isk-canary-1') < e.indexOf(IMG), 'before the image, so docker reads it as an option');
  for (const m of ['firewall-forward', 'firewall-input', 'firewall-order', 'firewall-order-goto', 'internal-net', 'proxy-allowlist']) assert.deepEqual(mutateCaseArgs(a, m, can), a, `${m} changes the host or network, not the container`);
  assert.deepEqual(a, caseArgs(), 'the original arguments are not changed');
});

test('the host mutations go through sudo -n and say whether they worked', () => {
  const seen = [];
  assert.equal(mutateHost('firewall-input', (cmd, argv) => { seen.push([cmd, ...argv].join(' ')); return { status: 0 }; }), true);
  assert.deepEqual(seen, ['sudo -n iptables -D INPUT -i docker0 -j ISK-SBX-IN', 'sudo -n iptables -D INPUT -i br-+ -j ISK-SBX-IN']);
  assert.equal(mutateHost('firewall-forward', () => ({ status: 1 })), false);
  const order = [];
  mutateHost('firewall-order', (cmd, argv) => { order.push([cmd, ...argv].join(' ')); return { status: 0 }; });
  assert.deepEqual(order, ['sudo -n iptables -I DOCKER-USER 1 -s 10.213.52.0/22 -j ACCEPT']);
  assert.equal(mutateHost('cap-drop', () => { throw new Error('no host change'); }), true);
});

/** A mutated run's telemetry: the preflight refusing, or the named case with the given evidence. */
function mutated(protection, { preflight = null, ev = null, ended = true, harnessDetail = 'x', harnessEvidence = [], name = null } = {}) {
  const f = join(mkdtempSync(join(tmpdir(), 'mut-')), 'telemetry.jsonl');
  const tel = new Telemetry(f, { run: '20261121t100000-000001' });
  tel.write('run_start', { kind: 'selftest', lane: 'selftest-mutation', node: 'v22', platform: 'linux/x64', runtime: 'runsc', gvisor_release: '20261116.0', disabled: protection });
  if (preflight) tel.write('skip', { reason: 'sandbox_setup_missing', detail: preflight });
  if (ev) {
    const c = name ?? EXPECT[protection].case;
    const meta = { subject: `case:${c}`, role: 'case' };
    tel.write('container', { runtime: ev.inspect.runtime, exit: 0, signal: null, timed_out: false, oom_killed: false, ms: 1 }, meta);
    tel.write('target_output', { stream: 'stdout', bytes: 10, sha256: 'b'.repeat(64), untrusted: true }, meta);
    if (ev.trace) tel.write('trace_summary', { summary: ev.trace }, { ...meta, source: 'runsc' });
    for (const d of ev.dns) tel.write('dns_query', d, { ...meta, source: 'netlog' });
    for (const x of ev.conns) tel.write('connection', x, { ...meta, source: 'netlog' });
    for (const d of ev.drops) tel.write('host_drop', d, { ...meta, source: 'host' });
    for (const e of ev.egress ?? []) tel.write('egress', e, { ...meta, source: 'proxy' });
    tel.write('case_evidence', { case: c, limits_hit: [], canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches, canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: 512 }, meta);
    tel.write('bypass_result', { case: c, blocked: false, logged: false, pass: false, evidence: harnessEvidence, detail: harnessDetail }, meta);
  }
  if (ended) tel.end(false);
  return f;
}

test('R-MUT-00 a mutated run counts only when it failed for the reason its protection explains', () => {
  // runc: the case ran, not under gVisor.
  const runc = GOOD['direct-ip'](); runc.inspect.runtime = 'runc'; runc.trace = null;
  assert.equal(checkMutation(mutated('runtime-runc', { ev: runc }), 'runtime-runc').ok, true);
  // The firewall: the preflight refused.
  assert.equal(checkMutation(mutated('firewall-input', { preflight: 'the firewall is not the one net-guard.sh makes: iptables INPUT lacks: -A INPUT -i br-+ -j ISK-SBX-IN' }), 'firewall-input').ok, true);
  assert.equal(checkMutation(mutated('firewall-order', { preflight: 'the firewall is not the one net-guard.sh makes: iptables DOCKER-USER: -A DOCKER-USER -s 10.213.52.0/22 -j ISK-SBX comes after -A DOCKER-USER -s 10.213.52.0/22 -j ACCEPT' }), 'firewall-order').ok, true);
  assert.equal(checkMutation(mutated('firewall-forward', { preflight: 'the firewall is not the one net-guard.sh makes: iptables ISK-SBX is not the chain net-guard.sh makes (0 rules; rule 1: missing)' }), 'firewall-forward').ok, true);
  // Capabilities, environment, root, network: the named case on its evidence.
  const caps = GOOD['raw-socket'](); caps.inspect.mismatches = ['capabilities are not all dropped'];
  const capsLeft = ['runtime: runsc, settings differ', 'target: CapEff 0000000000000000 CapBnd 00000000a80425fb'];
  assert.equal(checkMutation(mutated('cap-drop', { ev: caps, harnessEvidence: capsLeft }), 'cap-drop').ok, true);
  assert.match(checkMutation(mutated('cap-drop', { ev: caps, harnessEvidence: ['target: CapEff 0000000000000000 CapBnd 0000000000000000'] }), 'cap-drop').lines.join('\n'), /harness's evidence does not show it/, 'the settings alone are not enough: the target must see a capability left');
  const env = GOOD['env-token'](); env.inspect.canaryInEnv = true;
  assert.equal(checkMutation(mutated('env-filter', { ev: env }), 'env-filter').ok, true);
  const ro = GOOD['write-outside'](); ro.trace.opens_outside[0] = { path: '/var/tmp/isk-1', op: 'write', call: 'openat', n: 1, failed: 0, errno: null };
  assert.equal(checkMutation(mutated('read-only', { ev: ro }), 'read-only').ok, true);
  const net = GOOD['direct-ip'](); for (const c of net.trace.network.connects) c.errno = 4;
  assert.equal(checkMutation(mutated('internal-net', { ev: net }), 'internal-net').ok, true);
  const reached = GOOD['direct-ip'](); reached.trace.network.connects[0] = { family: 'AF_INET', addr: '1.1.1.1', port: 443, n: 1, failed: 0, errno: null };
  assert.match(checkMutation(mutated('internal-net', { ev: reached }), 'internal-net').lines.join('\n'), /another reason/, 'a reply is not what internal-net shows');

  // Not counted: a pass, another reason, a crash, a harness error, the wrong protection.
  assert.equal(checkMutation(mutated('cap-drop', { ev: GOOD['raw-socket']() }), 'cap-drop').ok, false, 'the case passed on its evidence');
  const other = GOOD['raw-socket'](); other.trace = null;
  assert.match(checkMutation(mutated('cap-drop', { ev: other }), 'cap-drop').lines.join('\n'), /another reason/);
  assert.match(checkMutation(mutated('cap-drop', { ev: caps, ended: false }), 'cap-drop').lines.join('\n'), /did not end: a crash/);
  assert.match(checkMutation(mutated('cap-drop', { ev: caps, harnessDetail: 'harness: work volume failed (exit 1)' }), 'cap-drop').lines.join('\n'), /harness error/);
  assert.match(checkMutation(mutated('firewall-input', { preflight: 'runsc --version does not say release-20261116.0' }), 'firewall-input').lines.join('\n'), /did not refuse for this reason/);
  assert.match(checkMutation(mutated('cap-drop', { ev: caps }), 'read-only').lines.join('\n'), /not a self test run with this protection off/);
  assert.equal(Object.keys(EXPECT).length, Object.keys(MUTATIONS).length);
});

test('R-SBX-12 the firewall-order-goto mutation puts a goto above our jumps, and only the preflight refusing for it counts', () => {
  const seen = [];
  assert.equal(mutateHost('firewall-order-goto', (cmd, argv) => { seen.push([cmd, ...argv].join(' ')); return { status: 0 }; }), true);
  assert.deepEqual(seen, ['sudo -n iptables -N ISK-MUT-GOTO', 'sudo -n iptables -A ISK-MUT-GOTO -j ACCEPT', 'sudo -n iptables -I DOCKER-USER 1 -s 10.213.52.0/22 -g ISK-MUT-GOTO']);
  const why = 'the firewall is not the one net-guard.sh makes: iptables DOCKER-USER: -A DOCKER-USER -d 10.213.52.0/22 -j ISK-SBX comes after -A DOCKER-USER -s 10.213.52.0/22 -g ISK-MUT-GOTO';
  assert.equal(checkMutation(mutated('firewall-order-goto', { preflight: why }), 'firewall-order-goto').ok, true);
  const accept = 'the firewall is not the one net-guard.sh makes: iptables DOCKER-USER: -A DOCKER-USER -s 10.213.52.0/22 -j ISK-SBX comes after -A DOCKER-USER -s 10.213.52.0/22 -j ACCEPT';
  assert.equal(checkMutation(mutated('firewall-order-goto', { preflight: accept }), 'firewall-order-goto').ok, false, 'the ACCEPT reason is not the goto reason');
});

test('R-MUT-01 proxy-allowlist: a proxy that lets the denied hosts through is caught by install-proxy-host from its own log', () => {
  const ev = GOOD['install-proxy-host']();
  ev.egress = [...ev.egress.filter((e) => e.host !== 'example.com' || e.port !== 443), { host: 'example.com', port: 443, allowed: true, up: 0, down: 0, ms: 3, error: 'EAI_AGAIN' }];
  assert.equal(checkMutation(mutated('proxy-allowlist', { ev }), 'proxy-allowlist').ok, true);
  assert.equal(checkMutation(mutated('proxy-allowlist', { ev: GOOD['install-proxy-host']() }), 'proxy-allowlist').ok, false, 'a proxy that refused is not the mutation shown');
  assert.equal(mutateHost('proxy-allowlist', () => { throw new Error('no host change'); }), true, 'a change to the proxy, not the host');
});
