import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, normalize } from 'node:path';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const WF = Object.fromEntries(readdirSync(new URL('../.github/workflows/', import.meta.url)).map((f) => [f, read(`.github/workflows/${f}`)]));
const code = (y) => y.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
// The body of one job: from its "  name:" key line to the next job key at the same indent.
const job = (y, name) => { const m = new RegExp(`\\n  ${name}:\\n([\\s\\S]*?)(?=\\n  [a-z][a-z0-9-]*:\\n|$)`).exec(y); assert.ok(m, `job ${name}`); return m[1]; };
// The job names: the two-space keys under the top-level "jobs:".
const jobsOf = (y) => [...code(y).split('\njobs:\n')[1].matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]);
// The steps of a job, in order, each as its text from "- " to the next step.
const steps = (body) => body.split('\n    steps:\n')[1].split(/\n(?=      - )/);
// The loop guard step of a workflow, read line by line: its env lines and its run block, dedented
// (comments kept, so two copies must agree to the character).
const guard = (y) => {
  const lines = y.split('\n');
  const i = lines.indexOf('      - id: guard');
  assert.ok(i >= 0, 'a step with id guard');
  assert.equal(lines[i + 1], '        name: Loop guard');
  assert.equal(lines[i + 2], '        env:');
  let k = i + 3;
  const env = [];
  while (lines[k].startsWith('          ')) env.push(lines[k++].trim());
  assert.equal(lines[k], '        run: |');
  const body = [];
  for (k += 1; k < lines.length && (lines[k] === '' || lines[k].startsWith('          ')); k += 1) body.push(lines[k].slice(10));
  while (body.length && body.at(-1) === '') body.pop();
  return { env, script: `${body.join('\n')}\n` };
};

test('there are exactly three workflows: ci, corpus and sandbox-selftest', () => {
  assert.deepEqual(Object.keys(WF).sort(), ['ci.yml', 'corpus.yml', 'sandbox-selftest.yml']);
});

test('every action is pinned by a full commit SHA with its version beside it', () => {
  for (const [f, y] of Object.entries(WF)) {
    const uses = [...code(y).matchAll(/uses:\s*(\S+)(.*)/g)];
    assert.ok(uses.length >= 3, f);
    for (const [, ref, rest] of uses) {
      assert.match(ref, /^actions\/(checkout|setup-node|upload-artifact|download-artifact)@[0-9a-f]{40}$/, `${f}: ${ref}`);
      assert.match(rest, /# v\d+\.\d+\.\d+/, `${f}: ${ref} has no version comment`);
    }
  }
});

test('least privilege: no token permission by default, every job asks for its own, one job with actions: read, no write anywhere', () => {
  for (const [f, y] of Object.entries(WF)) {
    assert.match(code(y), /\npermissions: \{\}\n/, `${f}: top-level permissions`);
    assert.ok(jobsOf(y).length >= 2, f);
    for (const j of jobsOf(y)) assert.match(job(code(y), j), /\n    permissions:(?: \{\}\n|\n      contents: read\n)/, `${f}: job ${j} declares its permissions`);
    assert.ok(!/:\s*write(?:-all)?\s*$/m.test(code(y)), `${f}: no write permission (a matrix value such as write-outside is not one)`);
    assert.ok(!/pull_request_target|workflow_run:/.test(code(y)), `${f}: no privileged trigger`);
    assert.ok(!/persist-credentials:\s*true/.test(y));
    for (const m of code(y).matchAll(/uses: actions\/checkout@[^\n]*\n((?:\s+.*\n)*?)(?=\s+- )/g)) assert.match(m[1], /persist-credentials: false/, `${f}: checkout keeps no credentials`);
  }
  assert.equal((code(WF['corpus.yml']).match(/actions: read/g) || []).length, 1);
  assert.match(job(code(WF['corpus.yml']), 'aggregate'), /permissions:\n      contents: read\n      actions: read/);
  assert.ok(!/actions: read/.test(code(WF['ci.yml'])));
});

test('ci: the required check ci-ok needs every other job and fails unless both succeeded', () => {
  const y = code(WF['ci.yml']);
  assert.match(y, /\non:\n  pull_request:\n  push:\n    branches: \[main\]/);
  const ok = job(y, 'ci-ok');
  assert.match(ok, /needs: \[test, example\]/);
  assert.match(ok, /if: always\(\)/);
  assert.match(ok, /\[ "\$r" = success \]/);
  assert.match(ok, /\[ "\$n" -eq 2 \]/);
  assert.ok(!/secrets\./.test(y), 'ci uses no secret');
  assert.ok(!/environment:/.test(y), 'ci uses no environment');
  assert.match(job(y, 'example'), /scripts\/run-example\.sh/);
  assert.match(job(y, 'example'), /SURFACE_DOCKER_TESTS: '1'/);
  assert.match(job(y, 'test'), /node --test test\/\*\.test\.mjs/);
});

test('ci: the example installs gVisor, then guards the networks (the daemon restart comes first), then runs targets', () => {
  const e = job(code(WF['ci.yml']), 'example');
  const at = (s) => { const i = e.indexOf(s); assert.ok(i >= 0, s); return i; };
  assert.match(e, /run: sudo scripts\/install-runsc\.sh "\$\(command -v node\)"/);
  assert.ok(at('actions/setup-node') < at('scripts/install-runsc.sh'), 'node is there for the plan');
  assert.ok(at('scripts/install-runsc.sh') < at('sudo scripts/net-guard.sh'));
  assert.ok(at('sudo scripts/net-guard.sh') < at('node --test test/driver.test.mjs'));
  assert.ok(at('node --test test/driver.test.mjs') < at('scripts/run-example.sh'));
});

test('corpus: nightly and by hand, one run at a time, a sharded matrix, never from a pull request', () => {
  const y = code(WF['corpus.yml']);
  assert.match(y, /schedule:\n\s+- cron: '\d+ \d+ \* \* \*'/);
  assert.match(y, /workflow_dispatch:/);
  // The triggers, read from the on: block itself (the loop guard's code names the pull_request event).
  const on = /\non:\n((?: {2}.*\n)+)/.exec(y)[1];
  assert.deepEqual([...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]), ['schedule', 'workflow_dispatch']);
  assert.ok(!/pull_request|push/.test(on));
  assert.match(y, /concurrency:\n  group: surface-corpus\n  cancel-in-progress: false/);
  assert.match(job(y, 'shard'), /matrix:\n        shard: \$\{\{ fromJSON\(needs\.plan\.outputs\.matrix\) \}\}/);
  assert.match(job(y, 'shard'), /fail-fast: false/);
  assert.match(job(y, 'shard'), /max-parallel: 16/);
  for (const j of ['plan', 'shard', 'aggregate']) assert.match(job(y, j), /github\.repository == 'isokron-ai\/mcp-surface-corpus' && github\.ref == 'refs\/heads\/main' && vars\.SURFACE_CORPUS_ENABLED == 'true'/, `${j} is gated`);
  for (const j of ['plan', 'shard', 'aggregate']) assert.match(job(y, j), /timeout-minutes: \d+/);
});

test('corpus: the loop guard comes first in the plan; nothing else runs, and no shard starts, unless it says go', () => {
  const y = code(WF['corpus.yml']);
  const plan = job(y, 'plan');
  const st = steps(plan);
  assert.match(st[0], /^      - id: guard\n/, 'the guard is the first step');
  assert.match(plan, /outputs:\n      go: \$\{\{ steps\.guard\.outputs\.go \}\}\n      slots: \$\{\{ steps\.guard\.outputs\.slots \}\}\n/);
  assert.ok(st.length >= 3);
  for (const s of st.slice(1)) assert.match(s, /\n        if: steps\.guard\.outputs\.go == 'true'\n/, `plan step runs only on go: ${s.trim().split('\n')[0]}`);
  assert.match(plan, /SLOTS_IN: \$\{\{ steps\.guard\.outputs\.slots \}\}\n\s+run: scripts\/check-batch\.sh output "\$GITHUB_OUTPUT"/);
  assert.match(job(y, 'shard'), /\n    if: needs\.plan\.outputs\.go == 'true' && github\.repository == /);
  assert.match(job(y, 'shard'), /SLOTS_IN: \$\{\{ needs\.plan\.outputs\.slots \}\}\n[\s\S]*?run: scripts\/check-batch\.sh env "\$GITHUB_ENV"/);
  assert.match(job(y, 'aggregate'), /\n    if: always\(\) && needs\.plan\.result == 'success' && needs\.plan\.outputs\.go == 'true' && github\.repository == /);
});

test('R-SBX-06 corpus: each shard installs gVisor, guards the networks, passes the self test, then decrypts the list and runs', () => {
  const s = job(code(WF['corpus.yml']), 'shard');
  const at = (x) => { const i = s.indexOf(x); assert.ok(i >= 0, x); return i; };
  assert.match(s, /run: sudo scripts\/install-runsc\.sh "\$\(command -v node\)"/);
  assert.ok(at('actions/setup-node') < at('scripts/install-runsc.sh'));
  assert.ok(at('scripts/install-runsc.sh') < at('sudo scripts/net-guard.sh'), 'the daemon restart comes before the firewall rules');
  assert.ok(at('sudo scripts/net-guard.sh') < at('node bin/sandbox-selftest.mjs'));
  assert.ok(at('node bin/sandbox-selftest.mjs') < at('node scripts/check-selftest.mjs'));
  assert.ok(at('node scripts/check-selftest.mjs') < at('scripts/decrypt-targets.sh'), 'the self test passes before the real list is decrypted');
  assert.ok(at('scripts/decrypt-targets.sh') < at('scripts/run-ci-shard.sh'));
});

test('corpus: the one secret is read by two steps only, in the corpus environment; the plan job has neither', () => {
  const y = code(WF['corpus.yml']);
  const secrets = [...y.matchAll(/\$\{\{\s*secrets\.([A-Z_]+)\s*\}\}/g)].map((m) => m[1]);
  assert.deepEqual(secrets, ['CORPUS_TARGETS_KEY', 'CORPUS_TARGETS_KEY']);
  assert.ok(!/environment:|secrets\./.test(job(y, 'plan')));
  assert.match(job(y, 'shard'), /environment: corpus/);
  assert.match(job(y, 'aggregate'), /environment: corpus/);
  // The steps that hold the key run one of our scripts and nothing else.
  for (const m of y.matchAll(/env:\n((?:\s{10}.*\n)+?)\s+run: (.*)/g)) if (m[1].includes('secrets.')) assert.match(m[2], /^scripts\/(decrypt-targets|aggregate-ci)\.sh$/);
  // The driver step gets the read-only token and no secret.
  const run = /- id: run\n[\s\S]*?run: scripts\/run-ci-shard\.sh/.exec(job(y, 'shard'))[0];
  assert.match(run, /GH_TOKEN: \$\{\{ github\.token \}\}/);
  assert.ok(!/secrets\./.test(run));
});

test('no workflow input or other expression reaches a shell line: they pass through env only', () => {
  for (const [f, y] of Object.entries(WF)) {
    const lines = code(y).split('\n');
    let inRun = false; let indent = 0;
    for (const l of lines) {
      const m = /^(\s*)(?:- )?run:\s*(.*)$/.exec(l);
      if (m) { inRun = m[2] === '|' || m[2] === '>'; indent = m[1].length; assert.ok(!l.includes('${{'), `${f}: expression in a run line: ${l.trim()}`); continue; }
      if (inRun) { if (l.trim() && l.search(/\S/) <= indent) inRun = false; else assert.ok(!l.includes('${{'), `${f}: expression in a run block: ${l.trim()}`); }
    }
  }
});

test('corpus: results are encrypted before upload; only the aggregate leaves in the clear, and never as an example', () => {
  const y = code(WF['corpus.yml']);
  const s = job(y, 'shard');
  assert.ok(s.indexOf('scripts/encrypt-results.sh') < s.indexOf('actions/upload-artifact'), 'encrypt, then upload');
  assert.match(s, /if: always\(\) && steps\.encrypt\.outcome == 'success'\n\s+uses: actions\/upload-artifact/);
  assert.match(s, /path: \$\{\{ runner\.temp \}\}\/corpus-upload\//);
  assert.ok(s.indexOf('sudo scripts/net-guard.sh') < s.indexOf('scripts/decrypt-targets.sh') && s.indexOf('scripts/decrypt-targets.sh') < s.indexOf('scripts/run-ci-shard.sh'));
  const uploads = [...y.matchAll(/path: \$\{\{ runner\.temp \}\}\/([a-z-]+)\//g)].map((m) => m[1]);
  assert.deepEqual(uploads, ['corpus-upload', 'aggregate-public', 'aggregate-private', 'aggregate-state']);
  for (const f of ['.github/workflows/corpus.yml', 'scripts/aggregate-ci.sh', 'scripts/run-ci-shard.sh', 'scripts/encrypt-results.sh']) assert.ok(!/--example|--min-cell|SURFACE_INSTALL_CA_FILE|SURFACE_IMAGE_MIRROR|SURFACE_SOURCE_CACHE/.test(read(f)), `${f}: no example or local-only switch`);
  assert.match(read('scripts/run-example.sh'), /--min-cell 1 --example/);
  assert.match(y, /retention-days: 90/);
});

test('the archive recipient is the existing corpus key, a public key, and the only one in the file', () => {
  const keys = read('recipients.txt').split('\n').filter((l) => l && !l.startsWith('#'));
  assert.deepEqual(keys, ['age13m0ee03crl6xgx4qtt3ffrgu354p3fw9zax06vr5pwh7237l29lswnw3w9']);
  for (const f of ['recipients.txt', 'scripts/encrypt-results.sh', 'scripts/aggregate-ci.sh', 'bin/pull-run.sh', 'bin/seal-targets.sh']) assert.ok(!/AGE-SECRET-KEY-1[A-Z0-9]{10,}/.test(read(f)), `${f}: no private key`);
});

test('the repository never holds a clear-text target list but the example', () => {
  assert.match(read('.gitignore'), /^targets\/\*\.json$/m);
  assert.match(read('.gitignore'), /^!targets\/example\.targets\.json$/m);
  assert.deepEqual(readdirSync(new URL('../targets/', import.meta.url)).filter((f) => f.endsWith('.json')), ['example.targets.json']);
});

test('sandbox-selftest: by hand or from a pull request that touches the sandbox; no secret, no environment, no token use', () => {
  const raw = WF['sandbox-selftest.yml'];
  const y = code(raw);
  assert.match(y, /\non:\n  workflow_dispatch:\n  pull_request:\n    paths:\n/);
  assert.ok(!/schedule:|\n  push:|pull_request_target|workflow_run/.test(y));
  assert.ok(!/secrets\.|environment:|github\.token|GH_TOKEN/.test(y), 'no secret, no environment, no token');
  assert.match(y, /\nconcurrency:\n  group: sandbox-selftest-\$\{\{ github\.ref \}\}\n  cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}\n/);
  assert.deepEqual(jobsOf(raw), ['gate', 'selftest', 'mutation']);
});

test('sandbox-selftest: the pull request filter covers every file the self test runs or imports, and names no missing file', () => {
  const lines = code(WF['sandbox-selftest.yml']).split('\n');
  const paths = [];
  for (let k = lines.indexOf('    paths:') + 1; /^      - \S+$/.test(lines[k]); k += 1) paths.push(lines[k].slice(8));
  const re = (g) => new RegExp(`^${g.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*')}$`);
  const covered = (f) => paths.some((g) => re(g).test(f));
  const all = (dir) => readdirSync(new URL(`../${dir}`, import.meta.url), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? all(`${dir}${e.name}/`) : [`${dir}${e.name}`]));
  const files = [...all('src/'), ...all('bin/'), ...all('scripts/'), ...all('sandbox/'), ...all('selftest/'), ...readdirSync(new URL('..', import.meta.url)), ...all('.github/workflows/')];
  for (const g of paths) assert.ok(files.some((f) => re(g).test(f)), `${g} names no file`);
  // Every local module the entry points import, followed through their imports.
  const seen = new Set();
  const queue = ['bin/sandbox-selftest.mjs', 'scripts/check-selftest.mjs', 'scripts/check-mutation.mjs', 'scripts/runsc-plan.mjs'];
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of read(f).matchAll(/\b(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)) queue.push(normalize(join(dirname(f), m[1])));
  }
  assert.ok(seen.size > 10);
  const need = [...seen, 'scripts/install-runsc.sh', 'scripts/net-guard.sh', 'selftest/hostile.py', 'sandbox/netlog.mjs', 'gvisor.json', 'images.json', '.github/workflows/sandbox-selftest.yml'];
  for (const f of need) {
    assert.ok(existsSync(new URL(`../${f}`, import.meta.url)), f);
    assert.ok(covered(f), `${f} is not in the pull_request paths`);
  }
  for (const m of code(WF['sandbox-selftest.yml']).matchAll(/\b((?:scripts|bin)\/[\w.-]+)/g)) assert.ok(covered(m[1]), `${m[1]} runs in the workflow but is not in the paths`);
});

test('sandbox-selftest: a gate job with the loop guard alone, then the self test under gVisor, checked from its telemetry, uploaded', () => {
  const y = code(WF['sandbox-selftest.yml']);
  const gate = job(y, 'gate');
  assert.ok(!/uses:/.test(gate), 'the gate checks nothing out and runs no action');
  assert.match(gate, /\n    permissions: \{\}\n/);
  assert.match(gate, /\n    timeout-minutes: [1-5]\n/);
  assert.match(gate, /\n    outputs:\n      go: \$\{\{ steps\.guard\.outputs\.go \}\}\n      slots: \$\{\{ steps\.guard\.outputs\.slots \}\}\n/);
  assert.equal(steps(gate).length, 1);
  assert.match(steps(gate)[0], /^      - id: guard\n/);
  const s = job(y, 'selftest');
  assert.match(s, /^    needs: gate\n/);
  assert.match(s, /\n    if: needs\.gate\.outputs\.go == 'true'\n/);
  assert.match(s, /\n    permissions:\n      contents: read\n    [a-z]/);
  const t = Number(/\n    timeout-minutes: (\d+)\n/.exec(s)[1]);
  assert.ok(t >= 10 && t <= 60, `timeout ${t}`);
  const order = [
    'uses: actions/checkout@',
    'uses: actions/setup-node@',
    'run: sudo scripts/install-runsc.sh "$(command -v node)"',
    'run: sudo scripts/net-guard.sh',
    'run: node bin/sandbox-selftest.mjs --out "$RUNNER_TEMP/selftest" --lane ci || echo "::warning::the harness reported a failure; the telemetry check decides"',
    'run: node scripts/check-selftest.mjs "$RUNNER_TEMP/selftest/telemetry.jsonl"',
    'uses: actions/upload-artifact@',
  ];
  const at = order.map((x) => { const i = s.indexOf(x); assert.ok(i >= 0, x); return i; });
  assert.deepEqual([...at].sort((p, q) => p - q), at, 'in this order');
  assert.equal(steps(s).length, order.length);
  const up = steps(s).at(-1);
  assert.match(up, /\n        if: always\(\)\n/);
  assert.match(up, /\n          path: \|\n            \$\{\{ runner\.temp \}\}\/selftest\/telemetry\.jsonl\n            \$\{\{ runner\.temp \}\}\/selftest\/results\.json\n/);
  assert.ok(!/untrusted/.test(up), 'what the hostile target printed is not uploaded');
});

test('the loop guard: one block, the same in corpus and sandbox-selftest; nothing runs unless LOOP_ENABLED is exactly true and LOOP_SLOTS at least 1', () => {
  const a = guard(WF['corpus.yml']);
  const b = guard(WF['sandbox-selftest.yml']);
  assert.deepEqual(a, b, 'the two copies agree to the character');
  assert.deepEqual(a.env, ['EVENT: ${{ github.event_name }}', 'LOOP_ENABLED: ${{ vars.LOOP_ENABLED }}', 'LOOP_SLOTS: ${{ vars.LOOP_SLOTS }}']);
  const d = mkdtempSync(join(tmpdir(), 'guard-'));
  const script = join(d, 'guard.sh');
  writeFileSync(script, a.script);
  // With no shell given, GitHub's Linux runners run a run block as `bash -e {file}`.
  const run = (env) => {
    const out = join(d, `out${Math.random()}`);
    writeFileSync(out, '');
    const r = spawnSync('bash', ['-e', script], { env: { PATH: process.env.PATH, GITHUB_OUTPUT: out, ...env }, encoding: 'utf8' });
    assert.equal(r.status, 0, `${JSON.stringify(env)}: the guard itself never fails the job: ${r.stdout}${r.stderr}`);
    return { out: readFileSync(out, 'utf8'), log: r.stdout + r.stderr };
  };
  const offs = [
    [{ EVENT: 'schedule' }, 'nothing set'],
    [{ EVENT: 'workflow_dispatch', LOOP_SLOTS: '4' }, 'slots without the switch'],
    [{ EVENT: 'schedule', LOOP_ENABLED: 'TRUE', LOOP_SLOTS: '4' }, 'not exactly true'],
    [{ EVENT: 'schedule', LOOP_ENABLED: 'true ', LOOP_SLOTS: '4' }, 'not exactly true'],
    [{ EVENT: 'schedule', LOOP_ENABLED: '1', LOOP_SLOTS: '4' }, 'not exactly true'],
    [{ EVENT: 'schedule', LOOP_ENABLED: 'false', LOOP_SLOTS: '4' }, 'off'],
    [{ EVENT: 'schedule', LOOP_ENABLED: 'true' }, 'slots default to 0'],
    ...['', '0', '000', '-1', 'x', '1000', '1.5', '2 ', ' 2', '1\ngo=true', '$(id)'].map((v) => [{ EVENT: 'workflow_dispatch', LOOP_ENABLED: 'true', LOOP_SLOTS: v }, `slots ${JSON.stringify(v)}`]),
  ];
  for (const [env, why] of offs) {
    const r = run(env);
    assert.equal(r.out, 'go=false\nslots=0\n', why);
    assert.match(r.log, /^::notice::/m, `${why}: the run says why it did nothing`);
    if (env.LOOP_SLOTS && /[^0-9]/.test(env.LOOP_SLOTS)) assert.ok(!r.log.includes(env.LOOP_SLOTS.trim()), `${why}: the value is not echoed`);
  }
  const ons = [
    [{ EVENT: 'schedule', LOOP_ENABLED: 'true', LOOP_SLOTS: '1' }, 'go=true\nslots=1\n'],
    [{ EVENT: 'workflow_dispatch', LOOP_ENABLED: 'true', LOOP_SLOTS: '12' }, 'go=true\nslots=12\n'],
    [{ EVENT: 'workflow_dispatch', LOOP_ENABLED: 'true', LOOP_SLOTS: '008' }, 'go=true\nslots=8\n'],
    [{ EVENT: 'workflow_dispatch', LOOP_ENABLED: 'true', LOOP_SLOTS: '999' }, 'go=true\nslots=999\n'],
    // A pull request runs its checks whatever the loop's switch says (corpus has no pull_request trigger).
    [{ EVENT: 'pull_request' }, 'go=true\nslots=1\n'],
    [{ EVENT: 'pull_request', LOOP_ENABLED: 'false', LOOP_SLOTS: '0' }, 'go=true\nslots=1\n'],
  ];
  for (const [env, want] of ons) assert.equal(run(env).out, want, JSON.stringify(env));
});

test('R-MUT-00 sandbox-selftest: a mutation job turns off each protection in turn and must see the self test fail for that reason', async () => {
  const { MUTATIONS } = await import('../bin/sandbox-selftest.mjs');
  const { EXPECT } = await import('../scripts/check-mutation.mjs');
  const m = job(code(WF['sandbox-selftest.yml']), 'mutation');
  assert.match(m, /^    needs: gate\n/);
  assert.match(m, /\n    permissions:\n      contents: read\n/);
  assert.ok(!/secrets\.|environment:/.test(m));
  const listed = [...m.matchAll(/\n          - disable: ([a-z-]+)\n/g)].map((x) => x[1]);
  assert.deepEqual(listed.sort(), Object.keys(MUTATIONS).sort(), 'every protection the switch knows is tried');
  assert.deepEqual(Object.keys(EXPECT).sort(), Object.keys(MUTATIONS).sort(), 'and each has an expected reason');
  for (const x of ['--lane selftest-mutation --disable "$DISABLE"', 'node scripts/check-selftest.mjs', 'node scripts/check-mutation.mjs']) assert.ok(m.includes(x), x);
  assert.ok(!/untrusted/.test(m));
});
