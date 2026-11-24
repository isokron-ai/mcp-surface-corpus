// The nightly conformance status (scripts/conformance-status.mjs), the runner facts next to it
// (scripts/runner-facts.mjs), and the pin drift proposals (scripts/pin-drift.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { STATUS_FORMAT, buildStatus, forMain, statusFrom, statusProblems, supersedes } from '../scripts/conformance-status.mjs';
import { verifyEvidence } from '../scripts/verify-conformance.mjs';
import { evidenceDir } from './evidence-fixtures.mjs';
import { plain, runnerFacts } from '../scripts/runner-facts.mjs';
import { applyPins, currentPins, describe, ghAttestationVerify, latestPins, openPr, readFiles, syncUses, tagCommit, workflowFiles } from '../scripts/pin-drift.mjs';

const root = new URL('..', import.meta.url).pathname;
const SHA = 'a'.repeat(40);
const good = {
  result: 'success', selftest: 'pass', mutations: 'pass', checkedAt: '2026-11-24T03:58:12Z', runId: '123456', runAttempt: '1',
  serverUrl: 'https://github.com', repo: 'isokron-ai/mcp-surface-corpus', sandboxSha: SHA, runnerImage: 'ubuntu24/20261117.1',
  kernel: '6.11.0-1018-azure', docker: '28.0.4', gvisorRelease: '20261116.0', runscVersion: 'release-20261116.0',
};

test('R-SBX-13 the conformance status is ok only when the call succeeded and both verdicts passed; anything missing counts against it', () => {
  const s = buildStatus(good);
  assert.equal(s.format, STATUS_FORMAT);
  assert.equal(s.ok, true);
  assert.equal(s.run_url, 'https://github.com/isokron-ai/mcp-surface-corpus/actions/runs/123456');
  assert.deepEqual(statusProblems(s), []);
  for (const [over, why] of [
    [{ result: 'failure' }, 'the call failed'],
    [{ result: 'cancelled' }, 'the call was cancelled'],
    [{ selftest: 'fail' }, 'the self test failed'],
    [{ selftest: '' }, 'no self test verdict'],
    [{ selftest: 'PASS' }, 'not exactly pass'],
    [{ mutations: 'skipped' }, 'the nightly needs the mutations'],
    [{ mutations: undefined }, 'no mutations verdict'],
  ]) {
    const r = buildStatus({ ...good, ...over });
    assert.equal(r.ok, false, why);
    assert.deepEqual(statusProblems(r), [], `${why}: a red status is still well formed, so it can be published`);
  }
  // Odd values never reach the file: they become unknown or null.
  const odd = buildStatus({ ...good, runnerImage: 'x\n::error::y', kernel: '$(id)', sandboxSha: 'nope', runId: '1; rm', checkedAt: 'yesterday', now: new Date('2026-11-24T05:00:00.123Z') });
  assert.equal(odd.runner_image, 'unknown');
  assert.equal(odd.kernel, 'unknown');
  assert.equal(odd.sandbox_sha, null);
  assert.equal(odd.run_id, null);
  assert.equal(odd.run_url, null);
  assert.equal(odd.checked_at, '2026-11-24T05:00:00Z', 'the publish time when the check never ran');
  assert.ok(JSON.stringify(buildStatus(good)).length < 1024, 'small');
  // A reader's rules.
  assert.deepEqual(statusProblems({ ...s, ok: true, mutations: 'fail' }), ['ok without both passes']);
  assert.ok(statusProblems({ ...s, format: 'other/1' }).includes('format'));
  assert.ok(statusProblems(null).length > 0);
});

test('R-SBX-13 conformance-status.mjs writes red and green alike (a red one must be published), from the evidence and its own environment', () => {
  const d = mkdtempSync(join(tmpdir(), 'status-'));
  const out = join(d, 'conformance-status.json');
  const run = (evidence, env) => spawnSync(process.execPath, [join(root, 'scripts/conformance-status.mjs'), '--evidence', evidence, '--prefix', 'nightly', '--out', out], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });
  const env = { CONFORMANCE_RESULT: 'success', GITHUB_RUN_ID: '9', GITHUB_RUN_ATTEMPT: '1', GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: good.repo, GITHUB_SHA: SHA };
  let r = run(evidenceDir('nightly'), env);
  assert.equal(r.status, 0, r.stderr);
  let s = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(s.ok, true, r.stdout);
  assert.equal(s.sandbox_sha, SHA);
  assert.equal(s.checked_at, '2026-11-20T03:58:12Z', 'the time the evidence ended');
  assert.equal(s.runner_image, 'ubuntu24/20261117.1');
  r = run(evidenceDir('nightly', { bad: 'direct-ip' }), env);
  assert.equal(r.status, 0, r.stderr);
  s = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(s.ok, false);
  assert.equal(s.selftest, 'fail');
  assert.match(r.stdout, /NOT OK/);
  assert.equal(spawnSync(process.execPath, [join(root, 'scripts/conformance-status.mjs')], { encoding: 'utf8' }).status, 2);
});

test('R-SBX-15 the published verdict is recomputed from the evidence in a job that ran no target; the self test jobs\' outputs are never read', () => {
  const now = new Date('2026-11-24T05:00:00Z');
  const ok = verifyEvidence(evidenceDir('nightly'), 'nightly', { now });
  assert.equal(ok.selftest, 'pass', ok.lines.join('\n'));
  assert.equal(ok.mutations, 'pass', ok.lines.join('\n'));
  for (const [opts, field, why] of [
    [{ bad: 'metadata' }, 'selftest', 'a case that got through'],
    [{ missing: ['selftest'] }, 'selftest', 'no self test evidence'],
    [{ missing: ['firewall-order-goto'] }, 'mutations', 'a mutation with no evidence'],
    [{ passing: ['cap-drop'] }, 'mutations', 'a mutation run that passed'],
  ]) assert.equal(verifyEvidence(evidenceDir('nightly', opts), 'nightly', { now })[field], 'fail', why);
  // A claim of "pass" in the environment cannot make one: only the evidence counts.
  const forged = statusFrom(evidenceDir('nightly', { bad: 'env-token' }), 'nightly', { CONFORMANCE_RESULT: 'success', SELFTEST: 'pass', MUTATIONS: 'pass', GITHUB_RUN_ID: '9', GITHUB_RUN_ATTEMPT: '1', GITHUB_REPOSITORY: good.repo, GITHUB_SHA: SHA }, now).status;
  assert.equal(forged.ok, false);
  assert.equal(forged.selftest, 'fail');
  // Evidence that claims a later time than now is held to now.
  assert.equal(verifyEvidence(evidenceDir('nightly', { end: '2027-01-01T00:00:00.000Z' }), 'nightly', { now }).checked_at, '2026-11-24T05:00:00Z');
  const wf = readFileSync(join(root, '.github/workflows/conformance-nightly.yml'), 'utf8');
  const publish = wf.slice(wf.indexOf('\n  publish:\n'));
  assert.ok(!/needs\.conformance\.outputs/.test(publish), 'the publish job reads no output of the jobs that ran targets');
  assert.match(publish, /uses: actions\/download-artifact@[0-9a-f]{40} # v[\d.]+\n        continue-on-error: true\n        with:\n          pattern: nightly-\*\n/);
  assert.match(publish, /node scripts\/conformance-status\.mjs --evidence "\$RUNNER_TEMP\/evidence" --prefix nightly --out /);
});

test('R-SBX-16 a status replaces the published one only when it is later and for main\'s head: a re-run never republishes an old green', async () => {
  const st = (o) => ({ ...buildStatus(good), ...o });
  const night1 = st({ run_id: 100, run_attempt: 1, checked_at: '2026-11-23T03:58:00Z' });
  const night2red = st({ run_id: 200, run_attempt: 1, checked_at: '2026-11-24T03:58:00Z', ok: false, selftest: 'fail' });
  assert.equal(supersedes(night2red, night1).ok, true);
  assert.equal(supersedes(st({ run_id: 100, run_attempt: 2, checked_at: '2026-11-23T03:58:00Z' }), night2red).ok, false, 're-run of night 1 over night 2');
  assert.equal(supersedes(st({ run_id: 200, run_attempt: 2, checked_at: '2026-11-24T04:30:00Z' }), night2red).ok, true, 'a later attempt of the same run');
  assert.equal(supersedes(st({ run_id: 200, run_attempt: 2, checked_at: '2026-11-23T00:00:00Z' }), night2red).ok, false, 'older evidence');
  assert.equal(supersedes(st({ run_id: 200, run_attempt: 1 }), night2red).ok, false, 'the same attempt again');
  assert.equal(supersedes(night1, null).ok, true, 'first publish');
  assert.equal(supersedes(night1, { junk: 1 }).ok, true, 'an unreadable old status');
  assert.equal(supersedes(st({ run_id: null }), null).ok, false, 'no run id');

  // The script: main's head and the published status come from gh; refusals upload nothing.
  const d = mkdtempSync(join(tmpdir(), 'pub-'));
  const bin = join(d, 'bin');
  spawnSync('mkdir', ['-p', bin, join(d, 'rel')]);
  writeFileSync(join(bin, 'gh'), `#!/bin/bash
echo "$*" >> "${d}/gh.log"
case "$1 $2" in
  "api repos/o/r/commits/main") cat "${d}/head" ;;
  "release view") [ -f "${d}/rel/conformance-status.json" ] && echo conformance-status.json; exit 0 ;;
  "release download") shift 2; while [ $# -gt 0 ]; do [ "$1" = --dir ] && cp "${d}/rel/conformance-status.json" "$2/"; shift; done ;;
  "release upload") cp "$4" "${d}/rel/conformance-status.json" ;;
esac
`, { mode: 0o755 });
  const publish = (status, head = SHA) => {
    writeFileSync(join(d, 'head'), `${head}\n`);
    const f = join(mkdtempSync(join(tmpdir(), 'st-')), 'conformance-status.json');
    writeFileSync(f, JSON.stringify(status));
    return spawnSync('bash', [join(root, 'scripts/publish-conformance.sh'), f], { env: { PATH: `${bin}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r' }, encoding: 'utf8' });
  };
  const published = () => JSON.parse(readFileSync(join(d, 'rel/conformance-status.json'), 'utf8'));
  let r = publish(night1);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(published().run_id, 100);
  r = publish(night2red);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(published().ok, false);
  r = publish(st({ run_id: 100, run_attempt: 2, checked_at: '2026-11-23T03:58:00Z' }));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /refused: run 100 attempt 2 is not later than the published run 200 attempt 1/);
  assert.equal(published().run_id, 200, 'the red stays');
  // A green for another commit than main's head is published as not ok (R-SBX-19).
  r = publish(st({ run_id: 300, run_attempt: 1, checked_at: '2026-11-25T03:58:00Z' }), 'c'.repeat(40));
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual([published().run_id, published().ok, published().result], [300, false, 'main_moved']);
  writeFileSync(join(d, 'junk.json'), '{}');
  assert.equal(publish({ hello: 'world' }).status, 1, 'not a status');
});

test('R-SBX-17 sandbox-guard runs only at a full commit SHA; a local checkout only with this repository\'s own switch', () => {
  const y = readFileSync(join(root, 'sandbox-guard/action.yml'), 'utf8');
  const lines = y.split('\n');
  const i = lines.indexOf('    - id: setup');
  const j = lines.indexOf('      run: |', i);
  const body = [];
  for (let k = j + 1; k < lines.length && (lines[k] === '' || lines[k].startsWith('        ')); k++) body.push(lines[k].slice(8));
  const d = mkdtempSync(join(tmpdir(), 'guard-'));
  writeFileSync(join(d, 'setup.sh'), `${body.join('\n')}\n`);
  const work = join(d, 'work');
  const ws = join(work, 'caller');
  const remote = (ref) => {
    const p = join(work, '_actions', 'isokron-ai', 'mcp-surface-corpus', ref, 'sandbox-guard');
    spawnSync('mkdir', ['-p', p]);
    return p;
  };
  const run = (actionPath, env = {}) => {
    const out = join(d, `o${Math.random()}`);
    writeFileSync(out, '');
    const r = spawnSync('bash', ['-e', join(d, 'setup.sh')], { env: { PATH: process.env.PATH, GITHUB_ACTION_PATH: actionPath, RUNNER_WORKSPACE: ws, RUNNER_OS: 'Linux', RUNNER_TEMP: d, GITHUB_OUTPUT: out, ALLOW_LOCAL: 'false', ...env }, encoding: 'utf8' });
    return { status: r.status, log: r.stdout + r.stderr, out: readFileSync(out, 'utf8') };
  };
  const sha = 'e'.repeat(40);
  let r = run(remote(sha));
  assert.equal(r.status, 0, r.log);
  assert.match(r.out, new RegExp(`^sha=${sha}$`, 'm'));
  for (const ref of ['main', 'v1', 'v1.2.3', 'feature/x', 'e'.repeat(39), `${'e'.repeat(40)}x`]) {
    r = run(remote(ref));
    assert.equal(r.status, 1, ref);
    assert.match(r.log, /use sandbox-guard at a full commit SHA/, ref);
  }
  r = run(remote(sha), { ACTION_REF: 'main' });
  assert.equal(r.status, 1, 'GitHub says the ref is a branch');
  // A local checkout: refused without the switch, allowed with it when the checkout is a commit.
  const local = join(d, 'checkout', 'sandbox-guard');
  spawnSync('mkdir', ['-p', local]);
  r = run(local);
  assert.equal(r.status, 1);
  assert.match(r.log, /only for this repository's sandbox-conformance\.yml/);
  r = run(local, { ALLOW_LOCAL: 'true' });
  assert.equal(r.status, 1, 'not a git checkout: no commit');
  spawnSync('git', ['-C', join(d, 'checkout'), 'init', '-q']);
  spawnSync('git', ['-C', join(d, 'checkout'), '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'x']);
  r = run(local, { ALLOW_LOCAL: 'true' });
  assert.equal(r.status, 0, r.log);
  assert.match(r.out, /^sha=[0-9a-f]{40}$/m);
  // Only the reusable workflow sets the switch.
  const wf = readFileSync(join(root, '.github/workflows/sandbox-conformance.yml'), 'utf8');
  assert.equal((wf.match(/allow-local-checkout: 'true'/g) || []).length, 1);
});

test('R-SBX-13 the runner facts are short plain tokens or unknown, whatever the commands print', () => {
  const run = (cmd) => ({
    uname: { status: 0, stdout: '6.11.0-1018-azure\n' },
    docker: { status: 0, stdout: '28.0.4\n' },
    runsc: { status: 0, stdout: 'runsc version release-20261116.0\nspec: 1.1.0\n' },
  }[cmd] ?? { status: 1, stdout: '' });
  const f = runnerFacts({ env: { ImageOS: 'ubuntu24', ImageVersion: '20261117.1', RUNNER_OS: 'Linux', RUNNER_ARCH: 'X64' }, run });
  assert.deepEqual(f, { format: 'isokron-sandbox-runner/1', runner_image: 'ubuntu24/20261117.1', runner_os: 'Linux', runner_arch: 'X64', kernel: '6.11.0-1018-azure', docker: '28.0.4', gvisor_release: JSON.parse(readFileSync(join(root, 'gvisor.json'), 'utf8')).release, runsc_version: 'release-20261116.0' });
  const bad = runnerFacts({ env: {}, run: () => ({ status: 0, stdout: 'a b\n' }), gvisor: '/nonexistent' });
  for (const k of ['runner_image', 'kernel', 'docker', 'gvisor_release', 'runsc_version']) assert.equal(bad[k], 'unknown', k);
  assert.equal(runnerFacts({ env: {}, run: () => { throw new Error('no such command'); } }).docker, 'unknown');
  assert.equal(plain('x=1\ny'), 'unknown');
  assert.equal(plain('::error::'), 'unknown');
});

// A fake network for pin-drift: the GitHub API and the download hosts.
function fakeNet({ gvisorTag = 'release-20261116.0', ageTag = 'v1.3.2', actionTags = {}, bundle = Buffer.from('bundle'), publishedSha512 = null, annotated = false }) {
  const calls = [];
  const sha512 = createHash('sha512').update(bundle).digest('hex');
  const fetchFn = async (url, init = {}) => {
    calls.push({ url, method: init.method ?? 'GET', body: init.body ? JSON.parse(init.body) : undefined, auth: new Headers(init.headers ?? {}).get('authorization') });
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
    const u = new URL(url);
    if (u.pathname === '/repos/google/gvisor/releases/latest') return json({ tag_name: gvisorTag });
    if (u.pathname === '/repos/FiloSottile/age/releases/latest') return json({ tag_name: ageTag });
    let m = /^\/repos\/(actions\/[a-z-]+)\/releases\/latest$/.exec(u.pathname);
    if (m) return json({ tag_name: actionTags[m[1]] ?? currentPins(readFiles(root)).actions[m[1]].version });
    m = /^\/repos\/(actions\/[a-z-]+)\/git\/ref\/tags\/(.+)$/.exec(u.pathname);
    if (m) return json({ object: annotated ? { type: 'tag', sha: 'c'.repeat(40) } : { type: 'commit', sha: 'b'.repeat(40) } });
    if (/\/git\/tags\/c{40}$/.test(u.pathname)) return json({ object: { type: 'commit', sha: 'd'.repeat(40) } });
    if (u.hostname === 'storage.googleapis.com' && u.pathname.endsWith('.sha512')) return new Response(`${publishedSha512 ?? sha512}  gvisor.tar.bz2\n`);
    if (u.hostname === 'storage.googleapis.com' || u.hostname === 'github.com') return new Response(bundle);
    return json({ message: 'not found' }, 404);
  };
  return { fetchFn, calls, sha512 };
}
const apiOf = (fetchFn) => async (path, { method = 'GET', body } = {}) => {
  const res = await fetchFn(`https://api.github.test${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await res.text();
  if (!res.ok) { const e = new Error(`${path}: ${res.status}`); e.status = res.status; throw e; }
  return t ? JSON.parse(t) : null;
};

test('R-SBX-14 pin drift: nothing behind proposes nothing; a newer gVisor, age or action is found, hashed and written into its own file only', async () => {
  const files = readFiles(root);
  const cur = currentPins(files);
  const same = fakeNet({});
  assert.deepEqual(describe(cur, await latestPins({ api: apiOf(same.fetchFn), fetchFn: same.fetchFn, current: cur })), []);
  assert.ok(!same.calls.some((c) => /storage\.googleapis|github\.com\/FiloSottile/.test(c.url)), 'nothing is downloaded when nothing moved');

  const net = fakeNet({ gvisorTag: 'release-20261201.0', ageTag: 'v1.4.0', actionTags: { 'actions/checkout': 'v7.1.0' } });
  const attested = [];
  const next = await latestPins({ api: apiOf(net.fetchFn), fetchFn: net.fetchFn, current: cur, verifyAge: (bytes, name) => { attested.push([bytes.toString(), name]); return true; } });
  assert.deepEqual(attested, [['bundle', 'age-v1.4.0-linux-amd64.tar.gz']], 'the age tarball is checked against its attestation');
  assert.deepEqual(describe(cur, next), [
    `gVisor ${cur.gvisor.release} -> 20261201.0 (gvisor.json)`,
    `age ${cur.age.version} -> v1.4.0 (scripts/install-age.sh; release attestation verified)`,
    `actions/checkout ${cur.actions['actions/checkout'].version} -> v7.1.0 (${'b'.repeat(40)}) (pins/actions.json)`,
  ]);
  const out = applyPins(files, cur, next, new Date('2026-12-02T06:17:00Z'));
  assert.deepEqual(Object.keys(out).sort(), ['gvisor.json', 'pins/actions.json', 'scripts/install-age.sh'], 'never a workflow file');
  const g = JSON.parse(out['gvisor.json']);
  assert.equal(g.release, '20261201.0');
  assert.equal(g.bundles.x86_64.url, 'https://storage.googleapis.com/gvisor/releases/release/20261201.0/x86_64/gvisor.tar.bz2');
  assert.equal(g.bundles.aarch64.sha512, net.sha512);
  assert.match(g.about, /Recorded 2 Dec 2026/);
  assert.deepEqual({ ...g, release: null, bundles: null, about: null }, { ...JSON.parse(files['gvisor.json']), release: null, bundles: null, about: null }, 'the flags, folders and trace settings are untouched');
  assert.match(out['scripts/install-age.sh'], /^AGE_URL=https:\/\/github\.com\/FiloSottile\/age\/releases\/download\/v1\.4\.0\/age-v1\.4\.0-linux-amd64\.tar\.gz$/m);
  assert.match(out['scripts/install-age.sh'], new RegExp(`^AGE_SHA256=${createHash('sha256').update(Buffer.from('bundle')).digest('hex')}$`, 'm'));
  assert.match(out['scripts/install-age.sh'], /^# age v1\.4\.0, linux-amd64 release tarball \(sha256 recorded 2 Dec 2026\)\.$/m);
  assert.deepEqual(JSON.parse(out['pins/actions.json']).actions['actions/checkout'], { sha: 'b'.repeat(40), version: 'v7.1.0' });
  // Then a person syncs the uses: lines; the other actions stay as they were.
  const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
  const synced = syncUses(ci, JSON.parse(out['pins/actions.json']).actions);
  assert.match(synced, new RegExp(`uses: actions/checkout@${'b'.repeat(40)} # v7\\.1\\.0`));
  assert.ok(!synced.includes(cur.actions['actions/checkout'].sha));
  assert.ok(synced.includes(cur.actions['actions/setup-node'].sha));
  assert.equal(syncUses(ci, cur.actions), ci, 'in sync already: no change');
  assert.ok(workflowFiles(root).includes('sandbox-guard/action.yml'));
});

test('R-SBX-14 pin drift trusts nothing it cannot check: a bundle whose sha512 differs from the published one, or an odd tag, stops it', async () => {
  const cur = currentPins(readFiles(root));
  const tampered = fakeNet({ gvisorTag: 'release-20261201.0', publishedSha512: 'f'.repeat(128) });
  await assert.rejects(latestPins({ api: apiOf(tampered.fetchFn), fetchFn: tampered.fetchFn, current: cur }), /sha512 differs from the published one/);
  const oddG = fakeNet({ gvisorTag: 'latest; rm -rf /' });
  await assert.rejects(latestPins({ api: apiOf(oddG.fetchFn), fetchFn: oddG.fetchFn, current: cur }), /not release-YYYYMMDD\.N/);
  const oddA = fakeNet({ ageTag: 'v1.4.0-rc1' });
  await assert.rejects(latestPins({ api: apiOf(oddA.fetchFn), fetchFn: oddA.fetchFn, current: cur }), /not vX\.Y\.Z/);
  // An annotated tag is followed to its commit.
  const ann = fakeNet({ annotated: true });
  assert.equal(await tagCommit(apiOf(ann.fetchFn), 'actions/checkout', 'v9.0.0'), 'd'.repeat(40));
});

test('R-SBX-14 pin drift opens one pull request through the API (tree, commit, branch, pull request), never twice for the same pins', async () => {
  const made = [];
  let branchExists = false;
  const api = async (path, { method = 'GET', body } = {}) => {
    made.push(`${method} ${path}`);
    if (method === 'GET' && path.startsWith('/repos/o/r/git/ref/heads/pin-drift/')) { if (branchExists) return { object: { sha: SHA } }; const e = new Error('404'); e.status = 404; throw e; }
    if (path === '/repos/o/r/git/ref/heads/main') return { object: { sha: SHA } };
    if (path === `/repos/o/r/git/commits/${SHA}`) return { tree: { sha: 't'.repeat(40) } };
    if (path === '/repos/o/r/git/trees') { assert.deepEqual(body.tree.map((t) => [t.path, t.mode, t.type]), [['gvisor.json', '100644', 'blob']]); return { sha: 'e'.repeat(40) }; }
    if (path === '/repos/o/r/git/commits') { assert.deepEqual(body.parents, [SHA]); return { sha: 'f'.repeat(40) }; }
    if (path === '/repos/o/r/git/refs') { assert.match(body.ref, /^refs\/heads\/pin-drift\/[0-9a-f]{12}$/); return {}; }
    if (path === '/repos/o/r/pulls') {
      assert.equal(body.base, 'main');
      assert.match(body.body, /cannot start workflows/);
      assert.match(body.body, /close and reopen/, 'no action pins: reopening starts the checks');
      return { number: 7, html_url: 'https://github.com/o/r/pull/7' };
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
  const pr = await openPr({ api, repo: 'o/r', changes: { 'gvisor.json': '{}\n' }, lines: ['gVisor a -> b (gvisor.json)'] });
  assert.equal(pr.number, 7);
  assert.deepEqual(made.map((m) => m.split(' ')[0]), ['GET', 'GET', 'GET', 'POST', 'POST', 'POST', 'POST']);
  branchExists = true;
  made.length = 0;
  assert.equal(await openPr({ api, repo: 'o/r', changes: { 'gvisor.json': '{}\n' }, lines: ['x'] }), null);
  assert.equal(made.length, 1, 'the same pins already proposed: nothing more is made');
});

test('R-SBX-14 publish-conformance.sh refuses anything but a well-formed status file, before touching a release', () => {
  const d = mkdtempSync(join(tmpdir(), 'pub-'));
  const bin = join(d, 'bin');
  spawnSync('mkdir', ['-p', bin]);
  // A gh that records its calls; main is at SHA, and there is no published status yet.
  writeFileSync(join(bin, 'gh'), `#!/bin/sh\necho "$@" >> "${d}/gh.log"\n[ "$1" = api ] && echo ${SHA}\n[ "$1 $2" = "release view" ] && exit 1\nexit 0\n`, { mode: 0o755 });
  const run = (file) => spawnSync('bash', [join(root, 'scripts/publish-conformance.sh'), file], { env: { PATH: `${bin}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r', GITHUB_SHA: SHA }, encoding: 'utf8' });
  const f = join(d, 'conformance-status.json');
  writeFileSync(f, JSON.stringify({ hello: 'world' }));
  assert.notEqual(run(f).status, 0);
  writeFileSync(join(d, 'other.json'), JSON.stringify(buildStatus(good)));
  assert.equal(run(join(d, 'other.json')).status, 2, 'only the status file name');
  let log = '';
  try { log = readFileSync(join(d, 'gh.log'), 'utf8'); } catch { /* none */ }
  assert.equal(log, '', 'gh was never called');
  writeFileSync(f, JSON.stringify(buildStatus({ ...good, result: 'failure' })));
  const r = run(f);
  assert.equal(r.status, 0, r.stderr);
  const log2 = readFileSync(join(d, 'gh.log'), 'utf8');
  assert.match(log2, /release create conformance --repo o\/r --target a{40} --prerelease --latest=false/, 'made on first use, never latest');
  assert.match(log2, /release upload conformance .*conformance-status\.json --repo o\/r --clobber/);
});

test('R-SBX-18 pin drift proposes no age without a valid release attestation, and says the gVisor and action pins are trust on first use', async () => {
  const cur = currentPins(readFiles(root));
  const net = fakeNet({ ageTag: 'v1.4.0' });
  const held = await latestPins({ api: apiOf(net.fetchFn), fetchFn: net.fetchFn, current: cur, verifyAge: () => false });
  assert.equal(held.age.version, cur.age.version, 'no age without a valid attestation (R-SBX-20)');
  // The default check is gh attestation verify, against age's own repository.
  const seen = [];
  assert.equal(ghAttestationVerify(Buffer.from('x'), 'age-v1.4.0-linux-amd64.tar.gz', (cmd, argv) => { seen.push([cmd, ...argv.map((a) => a.replace(/^.*\/(age-v[^/]+)$/, '<dir>/$1'))]); return { status: 0 }; }), true);
  assert.deepEqual(seen, [['gh', 'attestation', 'verify', '<dir>/age-v1.4.0-linux-amd64.tar.gz', '--repo', 'FiloSottile/age']]);
  assert.equal(ghAttestationVerify(Buffer.from('x'), 'a.tgz', () => ({ status: 1 })), false);
  // The pull request says which pins are trust on first use.
  let body = '';
  const api = async (path, { method = 'GET', body: b } = {}) => {
    if (method === 'GET' && path.includes('/git/ref/heads/pin-drift/')) { const e = new Error('404'); e.status = 404; throw e; }
    if (path.endsWith('/git/ref/heads/main')) return { object: { sha: SHA } };
    if (path.includes('/git/commits/')) return { tree: { sha: SHA } };
    if (path.endsWith('/pulls')) { body = b.body; return { number: 1, html_url: 'u' }; }
    return { sha: SHA };
  };
  await openPr({ api, repo: 'o/r', changes: { 'gvisor.json': '{}' }, lines: ['x'] });
  assert.match(body, /gVisor: \*\*trust on first use\.\*\*/);
  assert.match(body, /Actions: \*\*trust on first use\.\*\*/);
  assert.match(body, /gh attestation verify --repo FiloSottile\/age/);
});

test('R-SBX-19 a red status is always published when it supersedes, whatever main\'s head; a green for another commit goes up as not ok', () => {
  const st = (o) => ({ ...buildStatus(good), run_id: 10, run_attempt: 1, ...o });
  const red = st({ ok: false, selftest: 'fail' });
  assert.deepEqual(forMain(red, 'c'.repeat(40)).status, red, 'red stays red, published as it is');
  const moved = forMain(st({}), 'c'.repeat(40)).status;
  assert.equal(moved.ok, false);
  assert.equal(moved.result, 'main_moved');
  assert.deepEqual(statusProblems(moved), [], 'still a well-formed status a reader takes as not ok');
  assert.equal(forMain(st({}), SHA).status.ok, true, 'green for main\'s head stays green');

  // End to end: the sandbox broke, main moved during the run: the red still replaces the old green.
  const d = mkdtempSync(join(tmpdir(), 'pub19-'));
  const bin = join(d, 'bin');
  spawnSync('mkdir', ['-p', bin, join(d, 'rel')]);
  writeFileSync(join(d, 'rel/conformance-status.json'), JSON.stringify(st({ run_id: 9 })));
  writeFileSync(join(bin, 'gh'), `#!/bin/bash
case "$1 $2" in
  "api repos/o/r/commits/main") echo ${'c'.repeat(40)} ;;
  "release view") echo conformance-status.json ;;
  "release download") shift 2; while [ $# -gt 0 ]; do [ "$1" = --dir ] && cp "${d}/rel/conformance-status.json" "$2/"; shift; done ;;
  "release upload") cp "$4" "${d}/rel/conformance-status.json" ;;
esac
`, { mode: 0o755 });
  const f = join(mkdtempSync(join(tmpdir(), 'st-')), 'conformance-status.json');
  writeFileSync(f, JSON.stringify(red));
  const r = spawnSync('bash', [join(root, 'scripts/publish-conformance.sh'), f], { env: { PATH: `${bin}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r' }, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const now = JSON.parse(readFileSync(join(d, 'rel/conformance-status.json'), 'utf8'));
  assert.deepEqual([now.run_id, now.ok, now.selftest], [10, false, 'fail']);
});

test('R-SBX-20 an age release without a valid attestation is skipped, not fatal: gVisor and action pins still move, and the pull request lists the skip', async () => {
  const files = readFiles(root);
  const cur = currentPins(files);
  const net = fakeNet({ gvisorTag: 'release-20261201.0', ageTag: 'v1.4.0', actionTags: { 'actions/setup-node': 'v7.2.0' } });
  const next = await latestPins({ api: apiOf(net.fetchFn), fetchFn: net.fetchFn, current: cur, verifyAge: () => false });
  assert.equal(next.age.version, cur.age.version);
  assert.deepEqual(next.skipped, [`age ${cur.age.version} -> v1.4.0: release attestation missing or not valid; the pin stays at ${cur.age.version}`]);
  assert.deepEqual(describe(cur, next).map((l) => l.split(' ')[0]), ['gVisor', 'actions/setup-node']);
  assert.ok(!('scripts/install-age.sh' in applyPins(files, cur, next)));
  let body = '';
  const api = async (path, { method = 'GET', body: b } = {}) => {
    if (method === 'GET' && path.includes('/git/ref/heads/pin-drift/')) { const e = new Error('404'); e.status = 404; throw e; }
    if (path.endsWith('/git/ref/heads/main')) return { object: { sha: SHA } };
    if (path.includes('/git/commits/')) return { tree: { sha: SHA } };
    if (path.endsWith('/pulls')) { body = b.body; return { number: 1, html_url: 'u' }; }
    return { sha: SHA };
  };
  await openPr({ api, repo: 'o/r', changes: { 'gvisor.json': '{}' }, lines: describe(cur, next), skipped: next.skipped });
  assert.match(body, /\*\*Skipped \(not proposed\):\*\*\n\n- age .* -> v1\.4\.0: release attestation missing or not valid/);
});

test('R-SBX-21 the recompute says plainly what it does not defend against: a compromised self test runner', () => {
  for (const f of ['scripts/verify-conformance.mjs', '.github/workflows/conformance-nightly.yml', 'README.md']) {
    const t = readFileSync(join(root, f), 'utf8').replace(/\n(?:#|\/\/)? ?/g, ' ');
    assert.match(t, /not a defen[cs]e against a compromised self test runner/i, f);
    assert.match(t, /sign(?:s|ed)?[ -]provenance/i, `${f} names the real fix`);
  }
});
