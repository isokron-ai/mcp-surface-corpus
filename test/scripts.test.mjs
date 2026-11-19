import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { row } from './helpers.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const sh = (script, args, env) => spawnSync('bash', [join(root, script), ...args], { cwd: root, env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env }, encoding: 'utf8' });
const hasAge = spawnSync('age', ['--version']).status === 0 && spawnSync('age-keygen', ['--version']).status === 0;
const skipAge = !hasAge && 'age is not installed';

test('check-batch: the matrix comes from validated inputs only', () => {
  const d = mkdtempSync(join(tmpdir(), 'batch-'));
  const plan = (env) => { const f = join(d, `o${Math.random()}`); const r = sh('scripts/check-batch.sh', ['output', f], env); return r.status === 0 ? readFileSync(f, 'utf8').trim().split('\n') : `exit ${r.status}: ${r.stdout.trim()}`; };
  assert.deepEqual(plan({}), ['shards=8', 'matrix=[1,2,3,4,5,6,7,8]'], 'a scheduled run has no inputs: the whole list on 8 shards');
  assert.deepEqual(plan({ ONLY_IN: 's001,s014,s0200' }), ['shards=3', 'matrix=[1,2,3]']);
  assert.deepEqual(plan({ SHARDS_IN: '16' }), ['shards=16', 'matrix=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]']);
  assert.deepEqual(plan({ ONLY_IN: 's001,s002', SHARDS_IN: '9' }), ['shards=2', 'matrix=[1,2]'], 'never more shards than ids');
  assert.deepEqual(plan({ ONLY_IN: Array.from({ length: 40 }, (_, i) => `s${String(i + 1).padStart(3, '0')}`).join(',') }), ['shards=16', `matrix=[${Array.from({ length: 16 }, (_, i) => i + 1).join(',')}]`]);
  for (const bad of ['t01', 's1', 's001;rm -rf /', 's001,s001', 's001,s0001', 's001\nX=1', '$(id)', 's001, s002']) assert.match(plan({ ONLY_IN: bad }), /^exit 1/, JSON.stringify(bad));
  for (const bad of ['0', '17', 'x', '1\n2', '-1']) assert.match(plan({ SHARDS_IN: bad }), /^exit 1/, JSON.stringify(bad));
  const env = (e) => { const f = join(d, `e${Math.random()}`); const r = sh('scripts/check-batch.sh', ['env', f], e); return r.status === 0 ? readFileSync(f, 'utf8').trim().split('\n') : `exit ${r.status}`; };
  assert.deepEqual(env({ ONLY_IN: 's001,s002', PLAN_SHARDS: '2', SHARD: '2', JOB_INDEX: '1', JOB_TOTAL: '2' }), ['SURFACE_ONLY=s001,s002', 'SURFACE_SHARDS=2']);
  assert.equal(env({ ONLY_IN: 's001,s002', PLAN_SHARDS: '3', SHARD: '2', JOB_INDEX: '1', JOB_TOTAL: '2' }), 'exit 1', 'a plan that disagrees with the inputs');
  assert.equal(env({ ONLY_IN: 's001,s002', PLAN_SHARDS: '2', SHARD: '2', JOB_INDEX: '0', JOB_TOTAL: '2' }), 'exit 1', 'a matrix that disagrees with the shard');
  assert.equal(env({ PLAN_SHARDS: '8', SHARD: '9', JOB_INDEX: '8', JOB_TOTAL: '8' }), 'exit 1');
});

test('encrypt-results: two ciphertexts leave, rows readable by the CI key, everything else by the archive key only; no clear text stays', { skip: skipAge }, () => {
  const t = mkdtempSync(join(tmpdir(), 'enc-'));
  const c = join(t, 'corpus');
  mkdirSync(join(c, 'out', '_shard'), { recursive: true }); mkdirSync(join(c, 'out', 's001'));
  writeFileSync(join(c, 'out', 's001', 'record.json'), '{"secret":"target detail"}');
  writeFileSync(join(c, 'out', '_shard', 'rows.jsonl'), `${JSON.stringify(row(1))}\n`);
  writeFileSync(join(c, 'out', '_shard', 'state.jsonl'), '');
  writeFileSync(join(c, 'targets.json'), '{"leftover":true}');
  writeFileSync(join(c, 'public.txt'), 'run finished, exit 0\n');
  execFileSync('age-keygen', ['-o', join(t, 'ci.key')], { stdio: 'ignore' });
  writeFileSync(join(c, 'ci-recipient.txt'), execFileSync('age-keygen', ['-y', join(t, 'ci.key')]));
  const r = sh('scripts/encrypt-results.sh', [], { RUNNER_TEMP: t, SHARD: '3' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(readdirSync(join(t, 'corpus-upload')).sort(), ['surface-shard-3-rows.tgz.age', 'surface-shard-3.tgz.age']);
  assert.deepEqual(readdirSync(c).sort(), ['ci-recipient.txt', 'public.txt'], 'results, work folders and the list are gone');
  const rows = execFileSync('bash', ['-c', `age -d -i "${join(t, 'ci.key')}" "${join(t, 'corpus-upload', 'surface-shard-3-rows.tgz.age')}" | tar -xzO rows.jsonl`]).toString();
  assert.equal(JSON.parse(rows).id, 's001');
  const full = spawnSync('age', ['-d', '-i', join(t, 'ci.key'), join(t, 'corpus-upload', 'surface-shard-3.tgz.age')]);
  assert.notEqual(full.status, 0, 'the CI key cannot read the full bundle');
  assert.ok(!readFileSync(join(t, 'corpus-upload', 'surface-shard-3.tgz.age')).includes('target detail'));
});

test('aggregate-ci: reads the shards with the key, publishes two files, encrypts the rest', { skip: skipAge }, () => {
  const t = mkdtempSync(join(tmpdir(), 'aggci-'));
  execFileSync('age-keygen', ['-o', join(t, 'ci.key')], { stdio: 'ignore' });
  const key = readFileSync(join(t, 'ci.key'), 'utf8').split('\n').find((l) => l.startsWith('AGE-SECRET-KEY-'));
  const pub = execFileSync('age-keygen', ['-y', join(t, 'ci.key')]).toString().trim();
  writeFileSync(join(t, 'ci.pub'), `${pub}\n`);
  for (const n of [1, 2]) {
    const d = join(t, 'src', String(n)); mkdirSync(d, { recursive: true }); mkdirSync(join(t, 'shards', `surface-shard-${n}`), { recursive: true });
    writeFileSync(join(d, 'rows.jsonl'), Array.from({ length: 6 }, (_, i) => `${JSON.stringify(row(n * 10 + i))}\n`).join(''));
    writeFileSync(join(d, 'state.jsonl'), Array.from({ length: 6 }, (_, i) => `${JSON.stringify({ format: 'isokron-surface-state/1', id: `s0${n * 10 + i}`, tools: [], checks: [], grades: {} })}\n`).join(''));
    execFileSync('bash', ['-c', `tar -C "${d}" -czf - rows.jsonl state.jsonl | age -R "${join(root, 'recipients.txt')}" -R "${join(t, 'ci.pub')}" -o "${join(t, 'shards', `surface-shard-${n}`, `surface-shard-${n}-rows.tgz.age`)}"`]);
  }
  const r = sh('scripts/aggregate-ci.sh', [], { RUNNER_TEMP: t, CORPUS_TARGETS_KEY: key });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(r.stdout.trim(), 'aggregated 2 shard(s)');
  assert.deepEqual(readdirSync(join(t, 'aggregate-public')).sort(), ['aggregate.json', 'calibration.md']);
  const agg = JSON.parse(readFileSync(join(t, 'aggregate-public', 'aggregate.json'), 'utf8'));
  assert.deepEqual([agg.targets.total, agg.example, agg.min_cell, agg.shards], [12, false, 5, 2]);
  assert.ok(!/s0[12]\d/.test(JSON.stringify(agg)));
  assert.deepEqual(readdirSync(join(t, 'aggregate-private')), ['surface-aggregate-private.tgz.age']);
  assert.deepEqual(readdirSync(join(t, 'aggregate-state')), ['surface-state.tgz.age']);
  assert.equal(existsSync(join(t, 'aggregate-work')), false, 'the key file and every clear-text row are removed');
  const state = execFileSync('bash', ['-c', `age -d -i "${join(t, 'ci.key')}" "${join(t, 'aggregate-state', 'surface-state.tgz.age')}" | tar -xzO state.jsonl`]).toString().trim().split('\n');
  assert.equal(state.length, 12);
  assert.notEqual(spawnSync('age', ['-d', '-i', join(t, 'ci.key'), join(t, 'aggregate-private', 'surface-aggregate-private.tgz.age')]).status, 0, 'exact counts are for the archive key only');
  assert.notEqual(sh('scripts/aggregate-ci.sh', [], { RUNNER_TEMP: t }).status, 0, 'no key: stop');
});

test('seal-targets: validates, encrypts to two public keys, refuses a private key', { skip: skipAge }, () => {
  const t = mkdtempSync(join(tmpdir(), 'seal-'));
  execFileSync('age-keygen', ['-o', join(t, 'ci.key')], { stdio: 'ignore' });
  writeFileSync(join(t, 'ci.pub'), execFileSync('age-keygen', ['-y', join(t, 'ci.key')]));
  const ok = sh('bin/seal-targets.sh', [join(root, 'targets/example.targets.json'), join(t, 'ci.pub'), '--out', join(t, 'targets.json.age')], {});
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /3 target\(s\) valid: 2 npm, 1 pypi/);
  assert.equal(JSON.parse(execFileSync('age', ['-d', '-i', join(t, 'ci.key'), join(t, 'targets.json.age')]).toString()).targets.length, 3);
  assert.notEqual(sh('bin/seal-targets.sh', [join(root, 'targets/example.targets.json'), join(t, 'ci.key'), '--out', join(t, 'x.age')], {}).status, 0, 'a private key file is refused');
  writeFileSync(join(t, 'bad.json'), '{"format":"isokron-surface-targets/1","targets":[{"id":"x"}]}');
  assert.notEqual(sh('bin/seal-targets.sh', [join(t, 'bad.json'), join(t, 'ci.pub'), '--out', join(t, 'y.age')], {}).status, 0, 'an invalid list is not sealed');
  assert.equal(existsSync(join(t, 'y.age')), false);
});

test('pull-run: one run by id, all or nothing, decrypted beside the encrypted copy; the key is passed by path', { skip: skipAge }, () => {
  const t = mkdtempSync(join(tmpdir(), 'pull-'));
  const home = join(t, 'home'); const fix = join(t, 'fixtures'); const bin = join(t, 'bin');
  mkdirSync(home); mkdirSync(bin);
  execFileSync('age-keygen', ['-o', join(t, 'archive.key')], { stdio: 'ignore' });
  writeFileSync(join(t, 'archive.pub'), execFileSync('age-keygen', ['-y', join(t, 'archive.key')]));
  const bundle = (artifact, name, files) => {
    const src = join(t, 'src', name); mkdirSync(src, { recursive: true }); mkdirSync(join(fix, artifact), { recursive: true });
    for (const [p, text] of Object.entries(files)) { mkdirSync(join(src, p, '..'), { recursive: true }); writeFileSync(join(src, p), text); }
    execFileSync('bash', ['-c', `tar -C "${src}" -czf - . | age -R "${join(t, 'archive.pub')}" -o "${join(fix, artifact, `${name}.tgz.age`)}"`]);
  };
  bundle('surface-shard-1', 'surface-shard-1', { 's001/record.json': '{"target":"s001"}', '_shard/shard.json': '{}' });
  bundle('surface-shard-1', 'surface-shard-1-rows', { 'rows.jsonl': '{}\n' });
  bundle('surface-aggregate-private', 'surface-aggregate-private', { 'aggregate-exact.json': '{}' });
  mkdirSync(join(fix, 'surface-aggregate')); writeFileSync(join(fix, 'surface-aggregate', 'aggregate.json'), '{}'); writeFileSync(join(fix, 'surface-aggregate', 'calibration.md'), '# report\n');
  // A stand-in for gh: answers the four calls the script makes, from the fixtures.
  writeFileSync(join(bin, 'gh'), `#!/usr/bin/env bash
case "$1 $2" in
  "auth status") exit 0 ;;
  "run view") echo '{"databaseId":'"$3"',"createdAt":"2026-11-19T07:17:05Z","headSha":"abc","conclusion":"success","event":"schedule","attempt":1,"status":"'"\${FAKE_STATUS:-completed}"'","workflowName":"'"\${FAKE_WF:-corpus}"'"}' ;;
  "run list") printf '77\\t2026-11-19T07:17:05Z\\tcompleted\\tsuccess\\tschedule\\n' ;;
  "run download") n=""; d=""; while [ $# -gt 0 ]; do case "$1" in -n) n="$2"; shift ;; -D) d="$2"; shift ;; esac; shift; done; [ "$n" != "\${FAKE_MISSING:-}" ] || exit 1; mkdir -p "$d" && cp -R "${fix}/$n/." "$d/" ;;
  api\\ *) printf 'surface-shard-1\\tfalse\\nsurface-aggregate-private\\tfalse\\nsurface-aggregate\\t'"\${FAKE_EXPIRED:-false}"'\\n' ;;
  *) exit 2 ;;
esac
`, { mode: 0o755 });
  const env = { HOME: home, PATH: `${bin}:${process.env.PATH}`, SURFACE_ARCHIVE: join(t, 'archive'), CORPUS_KEY: join(t, 'archive.key') };
  const pull = (args, extra = {}) => sh('bin/pull-run.sh', args, { ...env, ...extra });
  const D = join(t, 'archive', '2026', '11', '19', 'gh-77');
  assert.match(pull(['77', '--dry-run']).stdout, /would download 3 artifact\(s\)/);
  assert.equal(existsSync(join(t, 'archive')), false, 'a dry run writes nothing');
  assert.notEqual(pull(['77'], { FAKE_WF: 'ci' }).status, 0, 'a run of another workflow is refused');
  assert.notEqual(pull(['77'], { FAKE_STATUS: 'in_progress' }).status, 0, 'a run that is not finished is refused');
  assert.notEqual(pull(['77'], { FAKE_EXPIRED: 'true' }).status, 0, 'an expired artifact: nothing is downloaded');
  assert.notEqual(pull(['77'], { FAKE_MISSING: 'surface-aggregate-private' }).status, 0);
  assert.equal(existsSync(join(D, 'encrypted')), false, 'a failed download keeps nothing');
  assert.notEqual(pull(['abc']).status, 0);
  const wrong = pull(['77'], { CORPUS_KEY: join(t, 'ci-wrong.key') });
  assert.notEqual(wrong.status, 0, 'no key file: the encrypted copy is kept, nothing is decrypted');
  assert.equal(existsSync(join(D, 'decrypted')), false);
  const r = pull(['77']);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /3 encrypted bundle\(s\)/);
  assert.match(r.stdout, /1 target record\(s\)/);
  assert.equal(readFileSync(join(D, 'decrypted', 'surface-shard-1', 's001', 'record.json'), 'utf8'), '{"target":"s001"}');
  assert.ok(existsSync(join(D, 'decrypted', 'surface-shard-1-rows', 'rows.jsonl')) && existsSync(join(D, 'decrypted', 'surface-aggregate-private', 'aggregate-exact.json')));
  assert.ok(existsSync(join(D, 'encrypted', 'surface-aggregate', 'calibration.md')));
  assert.deepEqual([JSON.parse(readFileSync(join(D, 'run-info.json'), 'utf8')).databaseId, JSON.parse(readFileSync(join(D, 'run-info.json'), 'utf8')).workflow], [77, 'surface-corpus']);
  assert.match(pull(['77']).stdout, /already downloaded/, 'a second run continues, it does not download again');
  assert.equal(pull(['--list']).stdout.trim().split('\t')[0], '77');
  const script = readFileSync(join(root, 'bin/pull-run.sh'), 'utf8');
  assert.ok(!/cat\s+"?\$CORPUS_KEY|<\s*"?\$CORPUS_KEY/.test(script), 'the key file is never read by the script');
  assert.ok(!/git (commit|push)/.test(script), 'it commits and pushes nothing');
});
