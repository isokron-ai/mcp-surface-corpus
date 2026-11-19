import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const WF = Object.fromEntries(readdirSync(new URL('../.github/workflows/', import.meta.url)).map((f) => [f, read(`.github/workflows/${f}`)]));
const code = (y) => y.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
// The body of one job: from its "  name:" key line to the next job key at the same indent.
const job = (y, name) => { const m = new RegExp(`\\n  ${name}:\\n([\\s\\S]*?)(?=\\n  [a-z][a-z0-9-]*:\\n|$)`).exec(y); assert.ok(m, `job ${name}`); return m[1]; };

test('there are exactly two workflows: ci and corpus', () => {
  assert.deepEqual(Object.keys(WF).sort(), ['ci.yml', 'corpus.yml']);
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

test('least privilege: read-only token by default, one job with actions: read, no write anywhere', () => {
  for (const [f, y] of Object.entries(WF)) {
    assert.match(code(y), /\npermissions:\n  contents: read\n/, `${f}: top-level permissions`);
    assert.ok(!/:\s*write\b/.test(code(y)), `${f}: no write permission`);
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

test('corpus: nightly and by hand, one run at a time, a sharded matrix, never from a pull request', () => {
  const y = code(WF['corpus.yml']);
  assert.match(y, /schedule:\n\s+- cron: '\d+ \d+ \* \* \*'/);
  assert.match(y, /workflow_dispatch:/);
  assert.ok(!/pull_request|\n  push:/.test(y));
  assert.match(y, /concurrency:\n  group: surface-corpus\n  cancel-in-progress: false/);
  assert.match(job(y, 'shard'), /matrix:\n        shard: \$\{\{ fromJSON\(needs\.plan\.outputs\.matrix\) \}\}/);
  assert.match(job(y, 'shard'), /fail-fast: false/);
  assert.match(job(y, 'shard'), /max-parallel: 16/);
  for (const j of ['plan', 'shard', 'aggregate']) assert.match(job(y, j), /github\.repository == 'isokron-ai\/mcp-surface-corpus' && github\.ref == 'refs\/heads\/main' && vars\.SURFACE_CORPUS_ENABLED == 'true'/, `${j} is gated`);
  for (const j of ['plan', 'shard', 'aggregate']) assert.match(job(y, j), /timeout-minutes: \d+/);
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
