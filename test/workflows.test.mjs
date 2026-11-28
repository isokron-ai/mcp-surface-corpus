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

test('there are exactly seven workflows: ci, corpus, sandbox-selftest, sandbox-conformance, conformance-nightly, pin-drift and mutation-probe', () => {
  assert.deepEqual(Object.keys(WF).sort(), ['ci.yml', 'conformance-nightly.yml', 'corpus.yml', 'mutation-probe.yml', 'pin-drift.yml', 'sandbox-conformance.yml', 'sandbox-selftest.yml']);
});

// The reusable workflow of this repository, and the sandbox guard action from the checked-out sandbox.
const LOCAL_USES = new Set(['./.github/workflows/sandbox-conformance.yml', './.isk-sandbox/sandbox-guard']);

test('every action is pinned by a full commit SHA with its version beside it, exactly as pins/actions.json records it', () => {
  const pins = JSON.parse(read('pins/actions.json')).actions;
  const seen = new Set();
  for (const [f, y] of Object.entries(WF)) {
    const uses = [...code(y).matchAll(/uses:\s*(\S+)(.*)/g)];
    assert.ok(uses.length >= 1, f);
    for (const [, ref, rest] of uses) {
      if (LOCAL_USES.has(ref)) continue;
      // The caller of tool-qa's reusable mutation-probe workflow: its shape is pinned by test/mutation-probe-caller.test.mjs.
      if (f === 'mutation-probe.yml' && /^isokron-ai\/tool-qa\/\.github\/workflows\/mutation-probe\.yml@[0-9a-f]{40}$/.test(ref)) continue;
      const m = /^(actions\/(?:checkout|setup-node|upload-artifact|download-artifact))@([0-9a-f]{40})$/.exec(ref);
      assert.ok(m, `${f}: ${ref}`);
      assert.match(rest, /# v\d+\.\d+\.\d+/, `${f}: ${ref} has no version comment`);
      assert.ok(pins[m[1]], `${f}: ${m[1]} is not in pins/actions.json`);
      assert.equal(m[2], pins[m[1]].sha, `${f}: ${m[1]} is not the commit pins/actions.json records (node scripts/pin-drift.mjs --sync-workflows)`);
      assert.equal(/# (v\d+\.\d+\.\d+)/.exec(rest)[1], pins[m[1]].version, `${f}: ${m[1]} version comment`);
      seen.add(m[1]);
    }
  }
  assert.deepEqual([...seen].sort(), Object.keys(pins).sort(), 'pins/actions.json lists only actions in use');
  assert.ok(!/uses:/.test(code(read('sandbox-guard/action.yml'))), 'the sandbox guard action runs no other action');
});

// The only write permissions: the nightly's publish job (the status release) and the pin-drift job
// (a branch and a pull request). Every other job reads at most.
const WRITERS = {
  'conformance-nightly.yml': { publish: 'contents: write' },
  'pin-drift.yml': { drift: 'contents: write\n      pull-requests: write' },
};

test('least privilege: no token permission by default, every job asks for its own, one job with actions: read, write only where named', () => {
  for (const [f, y] of Object.entries(WF)) {
    assert.match(code(y), /\npermissions: \{\}\n/, `${f}: top-level permissions`);
    assert.ok(jobsOf(y).length >= 1, f);
    for (const j of jobsOf(y)) {
      const w = WRITERS[f]?.[j];
      if (w) assert.match(job(code(y), j), new RegExp(`\\n    permissions:\\n      ${w}\\n    [a-z]`), `${f}: job ${j} has exactly its write permissions`);
      else assert.match(job(code(y), j), /\n    permissions:(?: \{\}\n|\n      contents: read\n)/, `${f}: job ${j} declares its permissions`);
    }
    const writes = (code(y).match(/:\s*write(?:-all)?\s*$/gm) || []).length;
    const allowed = Object.values(WRITERS[f] ?? {}).reduce((n, w) => n + w.split('\n').length, 0);
    assert.equal(writes, allowed, `${f}: no write permission but the named ones (a matrix value such as write-outside is not one)`);
    assert.ok(!/write-all|actions: write|id-token: write/.test(code(y)), `${f}: never write-all, actions: write or id-token: write`);
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
  for (const [f, y] of [...Object.entries(WF), ['sandbox-guard/action.yml', read('sandbox-guard/action.yml')]]) {
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
  assert.deepEqual(jobsOf(raw), ['gate', 'conformance', 'evidence']);
  const e = job(y, 'evidence');
  assert.match(e, /^    needs: \[gate, conformance\]\n    if: needs\.gate\.outputs\.go == 'true'\n/);
  assert.match(e, /\n    permissions:\n      contents: read\n/);
  assert.match(e, /pattern: sandbox-\*\n/);
  assert.match(e, /run: node scripts\/verify-conformance\.mjs --evidence "\$RUNNER_TEMP\/evidence" --prefix sandbox(?:\n|$)/);
  assert.ok(!/needs\.conformance\.outputs/.test(e), 'the evidence, not the claims');
  const c = job(y, 'conformance');
  assert.match(c, /^    needs: gate\n    if: needs\.gate\.outputs\.go == 'true'\n    permissions:\n      contents: read\n    uses: \.\/\.github\/workflows\/sandbox-conformance\.yml\n    with:\n      mutations: true\n/);
});

test('sandbox-selftest: the pull request filter covers every file the self test runs or imports, and names no missing file', () => {
  const lines = code(WF['sandbox-selftest.yml']).split('\n');
  const paths = [];
  for (let k = lines.indexOf('    paths:') + 1; /^      - \S+$/.test(lines[k]); k += 1) paths.push(lines[k].slice(8));
  const re = (g) => new RegExp(`^${g.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*')}$`);
  const covered = (f) => paths.some((g) => re(g).test(f));
  const all = (dir) => readdirSync(new URL(`../${dir}`, import.meta.url), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? all(`${dir}${e.name}/`) : [`${dir}${e.name}`]));
  const files = [...all('src/'), ...all('bin/'), ...all('scripts/'), ...all('sandbox/'), ...all('selftest/'), ...all('sandbox-guard/'), ...readdirSync(new URL('..', import.meta.url)), ...all('.github/workflows/')];
  for (const g of paths) assert.ok(files.some((f) => re(g).test(f)), `${g} names no file`);
  // Every local module the entry points import, followed through their imports.
  const seen = new Set();
  const queue = ['bin/sandbox-selftest.mjs', 'scripts/check-selftest.mjs', 'scripts/check-mutation.mjs', 'scripts/runsc-plan.mjs', 'scripts/runner-facts.mjs'];
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const m of read(f).matchAll(/\b(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)) queue.push(normalize(join(dirname(f), m[1])));
  }
  assert.ok(seen.size > 10);
  const need = [...seen, 'scripts/install-runsc.sh', 'scripts/net-guard.sh', 'selftest/hostile.py', 'sandbox/netlog.mjs', 'gvisor.json', 'images.json', '.github/workflows/sandbox-selftest.yml', '.github/workflows/sandbox-conformance.yml', 'sandbox-guard/action.yml'];
  for (const f of need) {
    assert.ok(existsSync(new URL(`../${f}`, import.meta.url)), f);
    assert.ok(covered(f), `${f} is not in the pull_request paths`);
  }
  for (const y of [WF['sandbox-selftest.yml'], WF['sandbox-conformance.yml'], read('sandbox-guard/action.yml')]) {
    for (const m of code(y).matchAll(/\b((?:scripts|bin)\/[\w.-]+)/g)) assert.ok(covered(m[1]), `${m[1]} runs in the self test but is not in the paths`);
  }
});

test('sandbox-selftest: a gate job with the loop guard alone, then the reusable conformance workflow of this same commit', () => {
  const y = code(WF['sandbox-selftest.yml']);
  const gate = job(y, 'gate');
  assert.ok(!/uses:/.test(gate), 'the gate checks nothing out and runs no action');
  assert.match(gate, /\n    permissions: \{\}\n/);
  assert.match(gate, /\n    timeout-minutes: [1-5]\n/);
  assert.match(gate, /\n    outputs:\n      go: \$\{\{ steps\.guard\.outputs\.go \}\}\n      slots: \$\{\{ steps\.guard\.outputs\.slots \}\}\n/);
  assert.equal(steps(gate).length, 1);
  assert.match(steps(gate)[0], /^      - id: guard\n/);
});

test('sandbox-conformance: a reusable workflow that tests the very commit it is pinned at; documented inputs and outputs', () => {
  const raw = WF['sandbox-conformance.yml'];
  const y = code(raw);
  const on = /\non:\n((?: {2}.*\n)+)/.exec(y)[1];
  assert.deepEqual([...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]), ['workflow_call'], 'workflow_call only');
  assert.deepEqual([...on.matchAll(/^ {6}([a-z-]+):$/gm)].map((m) => m[1]), ['mutations', 'artifact-prefix', 'verdict', 'selftest', 'mutations', 'telemetry-artifact', 'sandbox-sha', 'checked-at', 'runner-image', 'kernel', 'docker', 'gvisor-release', 'runsc-version']);
  assert.match(on, /      mutations:\n        description: [^\n]+\n        type: boolean\n        required: false\n        default: false\n/);
  assert.match(on, /      artifact-prefix:\n        description: [^\n]+\n        type: string\n        required: false\n        default: sandbox-conformance\n/);
  assert.ok(!/secrets\.|environment:|github\.token|GH_TOKEN/.test(y), 'no secret, no environment, no token');
  assert.deepEqual(jobsOf(raw), ['selftest', 'mutation', 'verdict']);
  // The README documents every input and output.
  const readme = read('README.md');
  for (const [, name] of on.matchAll(/^ {6}([a-z-]+):$/gm)) assert.match(readme, new RegExp(`\`${name}\``), `README documents ${name}`);
  // Both jobs that run the sandbox check out job.workflow_repository at job.workflow_sha, validated first.
  for (const j of ['selftest', 'mutation']) {
    const b = job(y, j);
    assert.match(b, /\n    permissions:\n      contents: read\n/);
    const st = steps(b);
    assert.match(st[0], /^      - id: which\n/);
    assert.match(st[0], /WF_REPO: \$\{\{ job\.workflow_repository \}\}\n\s+WF_SHA: \$\{\{ job\.workflow_sha \}\}/);
    assert.match(st[0], /\[\[ "\$WF_SHA" =~ \^\[0-9a-f\]\{40\}\$ \]\] \|\| \{ echo "::error::[^"]*"; exit 1; \}/);
    assert.match(st[0], /\[\[ "\$PREFIX" =~ \^\[a-z0-9\]\[a-z0-9-\]\{0,39\}\$ \]\]/);
    assert.match(st[1], /uses: actions\/checkout@[0-9a-f]{40} # v[\d.]+\n        with:\n          repository: \$\{\{ steps\.which\.outputs\.repo \}\}\n          ref: \$\{\{ steps\.which\.outputs\.sha \}\}\n          path: \.isk-sandbox\n          persist-credentials: false(?:\n|$)/);
    assert.match(st[2], /uses: actions\/setup-node@/);
  }
  const s = job(y, 'selftest');
  const t = Number(/\n    timeout-minutes: (\d+)\n/.exec(s)[1]);
  assert.ok(t >= 10 && t <= 60, `timeout ${t}`);
  const st = steps(s);
  assert.equal(st.length, 5);
  assert.match(st[3], /^      - id: guard\n        uses: \.\/\.isk-sandbox\/sandbox-guard\n        with:\n          out: \$\{\{ runner\.temp \}\}\/selftest(?:\n|$)/);
  assert.match(st[4], /\n        if: always\(\)\n/);
  assert.match(st[4], /\n          path: \|\n            \$\{\{ runner\.temp \}\}\/selftest\/telemetry\.jsonl\n            \$\{\{ runner\.temp \}\}\/selftest\/results\.json\n            \$\{\{ runner\.temp \}\}\/selftest\/environment\.json\n/);
  assert.ok(!/untrusted/.test(st[4]), 'what the hostile target printed is not uploaded');
  // The verdict job: never fails itself, needs both, and passes only on a success with a recomputed pass.
  const v = job(y, 'verdict');
  assert.match(v, /^    needs: \[selftest, mutation\]\n    if: always\(\)\n/);
  assert.match(v, /\n    permissions: \{\}\n/);
  assert.ok(!/exit 1/.test(v));
});

test('sandbox-conformance: the verdict step passes only on a selftest success with a recomputed pass, and every mutation shown when asked', () => {
  const v = steps(job(code(WF['sandbox-conformance.yml']), 'verdict'))[0];
  const lines = v.split('\n');
  const i = lines.indexOf('        run: |');
  const script = `${lines.slice(i + 1).map((l) => l.slice(10)).join('\n')}\n`;
  const d = mkdtempSync(join(tmpdir(), 'verdict-'));
  writeFileSync(join(d, 'v.sh'), script);
  const run = (env) => {
    const out = join(d, `o${Math.random()}`);
    writeFileSync(out, '');
    const r = spawnSync('bash', ['-e', join(d, 'v.sh')], { env: { PATH: process.env.PATH, GITHUB_OUTPUT: out, ARTIFACT: 'sandbox-selftest', ...env }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    return Object.fromEntries(readFileSync(out, 'utf8').trim().split('\n').map((l) => l.split('=')));
  };
  const ok = { SELFTEST_RESULT: 'success', SELFTEST_VERDICT: 'pass', MUTATION_RESULT: 'success', WANT_MUTATIONS: 'true' };
  assert.deepEqual(run(ok), { verdict: 'pass', selftest: 'pass', mutations: 'pass', artifact: 'sandbox-selftest' });
  assert.deepEqual(run({ ...ok, WANT_MUTATIONS: 'false', MUTATION_RESULT: 'skipped' }), { verdict: 'pass', selftest: 'pass', mutations: 'skipped', artifact: 'sandbox-selftest' });
  for (const [env, why] of [
    [{ SELFTEST_RESULT: 'failure' }, 'the self test job failed'],
    [{ SELFTEST_RESULT: 'cancelled' }, 'cancelled'],
    [{ SELFTEST_VERDICT: '' }, 'no recomputed verdict'],
    [{ SELFTEST_VERDICT: 'fail' }, 'a recomputed fail'],
    [{ MUTATION_RESULT: 'failure' }, 'a mutation not shown'],
    [{ MUTATION_RESULT: 'skipped' }, 'mutations asked for and skipped'],
  ]) assert.equal(run({ ...ok, ...env }).verdict, 'fail', why);
  assert.equal(run({ ...ok, ARTIFACT: 'x\ny=1' }).artifact, '', 'an odd artifact name is dropped');
});

test('sandbox-guard: gVisor, then net-guard, then the runner facts, the self test, and a check that fails the step unless it recomputed a pass', () => {
  const y = code(read('sandbox-guard/action.yml'));
  assert.match(y, /\nruns:\n  using: composite\n/);
  const order = [
    '- id: setup',
    'run: sudo bash "$ROOT/scripts/install-runsc.sh" "$(command -v node)"',
    'run: sudo bash "$ROOT/scripts/net-guard.sh"',
    'run: node "$ROOT/scripts/runner-facts.mjs" --out "$OUT/environment.json" --github-output "$GITHUB_OUTPUT"',
    'run: node "$ROOT/bin/sandbox-selftest.mjs" --out "$OUT" --lane ci || echo "::warning::the harness reported a failure; the telemetry check decides"',
    'if node "$ROOT/scripts/check-selftest.mjs" "$OUT/telemetry.jsonl"; then verdict=pass; else verdict=fail; fi',
    '[ "$verdict" = pass ] || { echo "::error::the sandbox self test did not pass: run no target on this runner"; exit 1; }',
  ];
  const at = order.map((x) => { const i = y.indexOf(x); assert.ok(i >= 0, x); return i; });
  assert.deepEqual([...at].sort((p, q) => p - q), at, 'in this order');
  assert.ok(!/secrets\.|github\.token|GH_TOKEN|GITHUB_TOKEN|untrusted\//.test(y.replace(/^#.*$/gm, '')), 'no token, no secret, nothing of the target');
  for (const o of ['sandbox-sha', 'verdict', 'out', 'checked-at', 'runner-image', 'kernel', 'docker', 'gvisor-release', 'runsc-version']) assert.match(y, new RegExp(`\\n  ${o}:\\n    description: `), `output ${o}`);
  assert.match(read('README.md'), /sandbox-guard/);
});

test('conformance-nightly: every night and by hand, no loop guard, the reusable workflow with mutations, then a public status published from main only', () => {
  const raw = WF['conformance-nightly.yml'];
  const y = code(raw);
  const on = /\non:\n((?: {2}.*\n)+)/.exec(y)[1];
  assert.deepEqual([...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]), ['schedule', 'workflow_dispatch']);
  assert.match(on, /schedule:\n    - cron: '\d+ \d+ \* \* \*'\n/, 'once a day');
  assert.ok(!/LOOP_ENABLED|LOOP_PAUSE_UNTIL|LOOP_SLOTS|LANE_/.test(y), 'a guard, not loop work: it runs whatever the loop switches say');
  assert.match(y, /\nconcurrency:\n  group: conformance-nightly\n  cancel-in-progress: false\n/);
  assert.deepEqual(jobsOf(raw), ['conformance', 'publish']);
  assert.match(job(y, 'conformance'), /^    if: github\.repository == 'isokron-ai\/mcp-surface-corpus'\n    permissions:\n      contents: read\n    uses: \.\/\.github\/workflows\/sandbox-conformance\.yml\n    with:\n      mutations: true\n      artifact-prefix: nightly\n/);
  const p = job(y, 'publish');
  assert.match(p, /^    needs: conformance\n    if: \$\{\{ !cancelled\(\) && github\.repository == 'isokron-ai\/mcp-surface-corpus' && github\.ref == 'refs\/heads\/main' \}\}\n/, 'a red result is published too; a cancelled run is not');
  assert.match(p, /\n    timeout-minutes: \d+\n/);
  const st = steps(p);
  assert.match(st[2], /uses: actions\/download-artifact@/);
  assert.match(st[3], /CONFORMANCE_RESULT: \$\{\{ needs\.conformance\.result \}\}\n/);
  assert.match(st[3], /node scripts\/conformance-status\.mjs --evidence "\$RUNNER_TEMP\/evidence" --prefix nightly --out "\$RUNNER_TEMP\/status\/conformance-status\.json"/);
  assert.ok(!/GH_TOKEN|github\.token/.test(st[3]), 'the status is written without a token');
  assert.ok(!/needs\.conformance\.outputs/.test(p), 'no output of a job that ran targets reaches the publish job');
  assert.match(st[4], /GH_TOKEN: \$\{\{ github\.token \}\}\n        run: scripts\/publish-conformance\.sh "\$RUNNER_TEMP\/status\/conformance-status\.json"\n?$/);
  assert.equal((y.match(/github\.token/g) || []).length, 1, 'only the publish step holds the token');
  assert.ok(!/secrets\.|environment:/.test(y));
});

test('pin-drift: weekly and by hand, contents and pull-requests write only, no kept credentials, one script', () => {
  const raw = WF['pin-drift.yml'];
  const y = code(raw);
  const on = /\non:\n((?: {2}.*\n)+)/.exec(y)[1];
  assert.deepEqual([...on.matchAll(/^ {2}([a-z_]+):/gm)].map((m) => m[1]), ['schedule', 'workflow_dispatch']);
  assert.match(on, /- cron: '\d+ \d+ \* \* [0-6]'\n/, 'once a week');
  assert.deepEqual(jobsOf(raw), ['drift']);
  const d = job(y, 'drift');
  assert.match(d, /^    if: github\.repository == 'isokron-ai\/mcp-surface-corpus' && github\.ref == 'refs\/heads\/main'\n/);
  assert.match(d, /\n    timeout-minutes: \d+\n/);
  assert.match(d, /\n          persist-credentials: false(?:\n|$)/);
  assert.match(d, /GITHUB_TOKEN: \$\{\{ github\.token \}\}\n          GH_TOKEN: \$\{\{ github\.token \}\}\n        run: node scripts\/pin-drift\.mjs --open-pr\n?$/);
  assert.ok(!/secrets\.|environment:|git push/.test(y));
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

test('R-MUT-00 sandbox-conformance: a mutation job turns off each protection in turn and must see the self test fail for that reason', async () => {
  const { MUTATIONS } = await import('../bin/sandbox-selftest.mjs');
  const { EXPECT } = await import('../scripts/check-mutation.mjs');
  const m = job(code(WF['sandbox-conformance.yml']), 'mutation');
  assert.match(m, /^    if: inputs\.mutations\n/);
  assert.match(m, /\n    permissions:\n      contents: read\n/);
  assert.ok(!/secrets\.|environment:/.test(m));
  const listed = [...m.matchAll(/\n          - disable: ([a-z-]+)\n/g)].map((x) => x[1]);
  assert.deepEqual(listed.sort(), Object.keys(MUTATIONS).sort(), 'every protection the switch knows is tried');
  assert.deepEqual(Object.keys(EXPECT).sort(), Object.keys(MUTATIONS).sort(), 'and each has an expected reason');
  for (const x of ['--lane selftest-mutation --disable "$DISABLE"', 'node .isk-sandbox/scripts/check-selftest.mjs', 'node .isk-sandbox/scripts/check-mutation.mjs']) assert.ok(m.includes(x), x);
  const at = (x) => { const i = m.indexOf(x); assert.ok(i >= 0, x); return i; };
  assert.ok(at('scripts/install-runsc.sh') < at('scripts/net-guard.sh') && at('scripts/net-guard.sh') < at('bin/sandbox-selftest.mjs'));
  assert.ok(!/untrusted/.test(m));
});
