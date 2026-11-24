// The nightly conformance status (scripts/conformance-status.mjs), the runner facts next to it
// (scripts/runner-facts.mjs), and the pin drift proposals (scripts/pin-drift.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { STATUS_FORMAT, buildStatus, statusProblems } from '../scripts/conformance-status.mjs';
import { plain, runnerFacts } from '../scripts/runner-facts.mjs';
import { applyPins, currentPins, describe, latestPins, openPr, readFiles, syncUses, tagCommit, workflowFiles } from '../scripts/pin-drift.mjs';

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

test('R-SBX-13 conformance-status.mjs writes red and green alike (a red one must be published), from the environment only', () => {
  const d = mkdtempSync(join(tmpdir(), 'status-'));
  const run = (env) => spawnSync(process.execPath, [join(root, 'scripts/conformance-status.mjs'), '--out', join(d, 'conformance-status.json')], { env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });
  const env = { CONFORMANCE_RESULT: 'failure', SELFTEST: 'fail', MUTATIONS: 'pass', CHECKED_AT: good.checkedAt, GITHUB_RUN_ID: '9', GITHUB_RUN_ATTEMPT: '1', GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: good.repo, SANDBOX_SHA: SHA, RUNNER_IMAGE: good.runnerImage, KERNEL: good.kernel, DOCKER: good.docker, GVISOR_RELEASE: good.gvisorRelease, RUNSC_VERSION: good.runscVersion };
  const r = run(env);
  assert.equal(r.status, 0, r.stderr);
  const s = JSON.parse(readFileSync(join(d, 'conformance-status.json'), 'utf8'));
  assert.equal(s.ok, false);
  assert.equal(s.selftest, 'fail');
  assert.match(r.stdout, /NOT OK/);
  assert.equal(run({ ...env, CONFORMANCE_RESULT: 'success', SELFTEST: 'pass' }).status, 0);
  assert.equal(JSON.parse(readFileSync(join(d, 'conformance-status.json'), 'utf8')).ok, true);
  assert.equal(spawnSync(process.execPath, [join(root, 'scripts/conformance-status.mjs')], { encoding: 'utf8' }).status, 2);
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
  const next = await latestPins({ api: apiOf(net.fetchFn), fetchFn: net.fetchFn, current: cur });
  assert.deepEqual(describe(cur, next), [
    `gVisor ${cur.gvisor.release} -> 20261201.0 (gvisor.json)`,
    `age ${cur.age.version} -> v1.4.0 (scripts/install-age.sh)`,
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
  // A gh that records its calls.
  writeFileSync(join(bin, 'gh'), `#!/bin/sh\necho "$@" >> "${d}/gh.log"\n`, { mode: 0o755 });
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
  assert.match(readFileSync(join(d, 'gh.log'), 'utf8'), /release upload conformance .*conformance-status\.json --repo o\/r --clobber/);
});
