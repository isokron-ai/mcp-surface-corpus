// The protection-off switch of the self test (bin/sandbox-selftest.mjs --disable) and the check that
// a mutated run failed for the reason the protection explains (scripts/check-mutation.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MUTATIONS, STAGE_MS, mutateCaseArgs, mutateHost, parseArgs } from '../bin/sandbox-selftest.mjs';
import { readFileSync } from 'node:fs';
import { LIMITS } from '../src/docker.mjs';
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
  for (const m of ['firewall-forward', 'firewall-input', 'firewall-order', 'firewall-order-goto', 'internal-net', 'proxy-allowlist', 'proxy-allowlist-empty', 'readout-follows-links', 'no-teardown', 'volume-cap', 'soft-teardown', 'target-time']) assert.deepEqual(mutateCaseArgs(a, m, can), a, `${m} changes the host or network, not the container`);
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
    tel.write('target_output', { stream: 'stdout', bytes: ev.output.bytes, sha256: 'b'.repeat(64), untrusted: true }, meta);
    if (ev.trace) tel.write('trace_summary', { summary: ev.trace }, { ...meta, source: 'runsc' });
    for (const d of ev.dns) tel.write('dns_query', d, { ...meta, source: 'netlog' });
    for (const x of ev.conns) tel.write('connection', x, { ...meta, source: 'netlog' });
    for (const d of ev.drops) tel.write('host_drop', d, { ...meta, source: 'host' });
    for (const e of ev.egress ?? []) tel.write('egress', e, { ...meta, source: 'proxy' });
    tel.write('case_evidence', { case: c, limits_hit: [], canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches, canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: 512, ...(ev.stage ? { stage: ev.stage } : {}) }, meta);
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

test('R-MUT-02 proxy-allowlist-empty: a proxy that refuses everything is caught by the positive control, not passed on its refusals', () => {
  const ev = GOOD['install-proxy-host']();
  ev.egress = [...ev.egress.filter((e) => e.allowed !== true), { host: 'registry.npmjs.org', port: 443, allowed: false, error: 'host not on the allowlist' }];
  const r = checkMutation(mutated('proxy-allowlist-empty', { ev }), 'proxy-allowlist-empty');
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(checkMutation(mutated('proxy-allowlist-empty', { ev: GOOD['install-proxy-host']() }), 'proxy-allowlist-empty').ok, false, 'a working proxy is not the mutation shown');
  assert.equal(MUTATIONS['proxy-allowlist-empty'].includes('allows nothing'), true);
});

test('R-MUT-03 readout-follows-links: a readout that reads a path as it is, links and all, is caught by symlink-escape', () => {
  const ev = GOOD['symlink-escape']();
  ev.stage.readout = ev.stage.readout.map((r) => ({ ...r, exit: 0, bytes: 900 }));
  const r = checkMutation(mutated('readout-follows-links', { ev }), 'readout-follows-links');
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(checkMutation(mutated('readout-follows-links', { ev: GOOD['symlink-escape']() }), 'readout-follows-links').ok, false, 'a readout that refused is not the mutation shown');
  const host = GOOD['symlink-escape'](); host.stage.host.planted = 2;
  assert.match(checkMutation(mutated('readout-follows-links', { ev: host }), 'readout-follows-links').lines.join('\n'), /another reason/);
  assert.equal(mutateHost('readout-follows-links', () => { throw new Error('no host change'); }), true);
});

test('R-MUT-04 no-teardown: a server-like case left running after its stage is caught by unix-socket\'s later stage', () => {
  const ev = GOOD['unix-socket']();
  ev.stage.reach[0] = { to: 'tcp 10.213.53.3:47124', ok: true, code: 'answered', bytes: 22 };
  const r = checkMutation(mutated('no-teardown', { ev }), 'no-teardown');
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(checkMutation(mutated('no-teardown', { ev: GOOD['unix-socket']() }), 'no-teardown').ok, false);
  const sock = GOOD['unix-socket'](); sock.stage.reach[1].ok = true;
  assert.match(checkMutation(mutated('no-teardown', { ev: sock }), 'no-teardown').lines.join('\n'), /another reason/, 'only the TCP listener outlives a stage that was not torn down');
  assert.equal(STAGE_MS['unix-socket'] > 0 && STAGE_MS['unix-socket'] <= 60_000, true);
});

test('R-MUT-05 volume-cap: a work volume on the runner\'s own disk is caught by install-archive-bomb', () => {
  const ev = GOOD['install-archive-bomb']();
  Object.assign(ev.stage.disk, { host_free_drop_mb: 8200, work_fs_mb: 73000, work_fs_inodes: 9_000_000 });
  const r = checkMutation(mutated('volume-cap', { ev }), 'volume-cap');
  assert.equal(r.ok, true, r.lines.join('\n'));
  const big = GOOD['install-archive-bomb'](); big.stage.disk.work_fs_mb = 73000;
  assert.equal(checkMutation(mutated('volume-cap', { ev: big }), 'volume-cap').ok, true, 'the volume past its cap shows it too');
  assert.equal(checkMutation(mutated('volume-cap', { ev: GOOD['install-archive-bomb']() }), 'volume-cap').ok, false);
  assert.match(MUTATIONS['volume-cap'], /runner's own disk/);
});

test('R-MUT-06 log-cap: a container that keeps its output as Docker does by default is caught by output-flood from what Docker kept', () => {
  const a = caseArgs();
  const b = mutateCaseArgs(a, 'log-cap', {});
  assert.equal(b[b.indexOf('--log-driver') + 1], 'json-file');
  assert.ok(!b.includes('--log-opt'), 'no size limit');
  assert.equal(a.length - b.length, 4);
  const ev = GOOD['output-flood'](); ev.output.bytes = 2 * 1024 ** 3; ev.inspect.mismatches = ['no log limit declared'];
  const r = checkMutation(mutated('log-cap', { ev }), 'log-cap');
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(checkMutation(mutated('log-cap', { ev: GOOD['output-flood']() }), 'log-cap').ok, false, 'a flood kept within the cap is not the mutation shown');
  const disk = GOOD['output-flood'](); disk.stage.disk.host_free_drop_mb = 900;
  assert.match(checkMutation(mutated('log-cap', { ev: disk }), 'log-cap').lines.join('\n'), /another reason/);
});

test('R-MUT-07 git-env: GIT_CONFIG_* allowing every transport is caught by install-git-submodule (ext:: runs, file:// is followed)', () => {
  const b = mutateCaseArgs(caseArgs(), 'git-env', {});
  assert.ok(b.includes('GIT_CONFIG_KEY_1=protocol.ext.allow') && b.indexOf('GIT_CONFIG_COUNT=3') < b.indexOf(IMG));
  for (const f of [(ev) => { ev.stage.git.ext_ran = true; }, (ev) => { ev.stage.git.file_followed = true; }]) {
    const ev = GOOD['install-git-submodule'](); f(ev); ev.inspect.mismatches = ['environment has GIT_CONFIG_COUNT'];
    const r = checkMutation(mutated('git-env', { ev }), 'git-env');
    assert.equal(r.ok, true, r.lines.join('\n'));
  }
  assert.equal(checkMutation(mutated('git-env', { ev: GOOD['install-git-submodule']() }), 'git-env').ok, false);
});

test('R-MUT-08 soft-teardown: a stage torn down with TERM only is caught by background\'s heartbeats', () => {
  const ev = GOOD.background(); ev.stage.grow[0].after = 80;
  assert.equal(checkMutation(mutated('soft-teardown', { ev }), 'soft-teardown').ok, true);
  assert.equal(checkMutation(mutated('soft-teardown', { ev: GOOD.background() }), 'soft-teardown').ok, false);
  assert.match(MUTATIONS['soft-teardown'], /--signal TERM/);
  assert.equal(STAGE_MS.background > 0 && STAGE_MS.background <= 60_000, true);
});

test('R-MUT-09 runc-proc: proc-sys under runc is caught by the host facts in its output, not by the runtime alone', () => {
  assert.equal(mutateCaseArgs(caseArgs(), 'runc-proc', {})[caseArgs().indexOf('--runtime') + 1], 'runc');
  const ev = GOOD['proc-sys'](); ev.inspect.runtime = 'runc'; ev.stage.host_facts.seen = ['kernel'];
  assert.equal(checkMutation(mutated('runc-proc', { ev }), 'runc-proc').ok, true);
  const bare = GOOD['proc-sys'](); bare.inspect.runtime = 'runc';
  assert.match(checkMutation(mutated('runc-proc', { ev: bare }), 'runc-proc').lines.join('\n'), /another reason/, 'not run under gVisor is not enough: a host fact must show');
});

test('R-MUT-10 nofile: a container without the descriptor limit is caught by fd-exhaustion', () => {
  const b = mutateCaseArgs(caseArgs(), 'nofile', {});
  assert.ok(!b.includes(`nofile=${LIMITS.nofile}:${LIMITS.nofile}`) && caseArgs().length - b.length === 2);
  const ev = GOOD['fd-exhaustion'](); ev.trace.network.sockets[0] = { ...ev.trace.network.sockets[0], n: 20000, failed: 0, errno: null };
  assert.equal(checkMutation(mutated('nofile', { ev }), 'nofile').ok, true);
  assert.equal(checkMutation(mutated('nofile', { ev: GOOD['fd-exhaustion']() }), 'nofile').ok, false);
});

test('R-MUT-11 target-time: a harness that takes the target\'s claimed time is caught by clock-tamper', () => {
  const ev = GOOD['clock-tamper'](); ev.stage.clock.forged_in_telemetry = true;
  assert.equal(checkMutation(mutated('target-time', { ev }), 'target-time').ok, true);
  assert.equal(checkMutation(mutated('target-time', { ev: GOOD['clock-tamper']() }), 'target-time').ok, false);
  const st = readFileSync(new URL('../bin/sandbox-selftest.mjs', import.meta.url), 'utf8');
  assert.ok(st.indexOf('if (Number.isFinite(claimed)) tel.clock') < st.indexOf("tel.write('target_output', { stream: 'stdout'") && st.indexOf("tel.write('target_output', { stream: 'stderr'") < st.indexOf('tel.clock = ownClock;'), 'only the output records, and the clock put back');
});
