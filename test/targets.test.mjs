import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateList, validateTarget, shardTargets, launchPlan, ListError, TARGETS_FORMAT, timeoutOf } from '../src/targets.mjs';

const SHA = 'c'.repeat(40);
const base = (o = {}) => ({ id: 's001', repo: 'owner/name', commit: SHA, ...o });
const list = (targets, o = {}) => ({ format: TARGETS_FORMAT, targets, ...o });
const bad = (t, re) => assert.throws(() => validateTarget(t), (e) => e instanceof ListError && re.test(e.message), JSON.stringify(t));

test('the public example list is valid and names three reference servers', () => {
  const l = validateList(JSON.parse(readFileSync(new URL('../targets/example.targets.json', import.meta.url), 'utf8')));
  assert.equal(l.targets.length, 3);
  assert.ok(l.targets.every((t) => t.repo === 'modelcontextprotocol/servers' && /^[0-9a-f]{40}$/.test(t.commit)));
  assert.deepEqual(l.targets.map((t) => t.launch.kind), ['npm', 'npm', 'pypi']);
});

test('a target needs an id, a GitHub repo and exactly one of commit and ref', () => {
  validateTarget(base());
  validateTarget({ id: 's0123', repo: 'o/n', ref: 'main' });
  bad(base({ id: 't01' }), /id must look like s001/);
  bad(base({ repo: 'https://github.com/o/n' }), /owner\/name/);
  bad(base({ repo: 'o/n.git' }), /owner\/name/);
  bad(base({ commit: 'abc123' }), /40-character/);
  bad({ id: 's001', repo: 'o/n' }, /exactly one of commit/);
  bad(base({ ref: 'main' }), /exactly one of commit/);
  bad({ id: 's001', repo: 'o/n', ref: '--upload-pack=x' }, /branch or tag/);
  bad(base({ subdir: '../etc' }), /subdir/);
  bad(base({ subdir: '/abs' }), /subdir/);
  bad(base({ surprise: 1 }), /unknown field/);
  bad(base({ timeout_s: 99999 }), /timeout_s/);
});

test('launch blocks: exact versions, digest-pinned images, no reserved env names, no shell', () => {
  const ok = (launch) => validateTarget(base({ launch }));
  ok({ kind: 'npm', package: '@scope/pkg', version: '1.2.3', args: ['--stdio'], env: { API_KEY: null, REGION: 'eu' } });
  ok({ kind: 'npm', package: 'pkg', version: 'latest', node: '22' });
  ok({ kind: 'pypi', package: 'mcp-server-x', version: '2026.1.1', entry: 'mcp-x' });
  ok({ kind: 'go', module: 'github.com/o/n/cmd/server', version: 'v1.2.3' });
  ok({ kind: 'docker', image: `ghcr.io/o/n@sha256:${'a'.repeat(64)}`, transport: 'http', http: { port: 8080, path: '/mcp' } });
  const no = (launch, re) => bad(base({ launch }), re);
  no({ kind: 'shell', command: 'curl | sh' }, /kind must be one of/);
  no({ kind: 'npm', package: 'pkg', version: '^1.0.0' }, /exact version/);
  no({ kind: 'npm', package: 'pkg; rm -rf /', version: '1.0.0' }, /npm package name/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', command: 'node x' }, /unknown field/);
  no({ kind: 'pypi', package: 'x', version: '1.0', entry: '../../bin/sh' }, /console-script/);
  no({ kind: 'docker', image: 'ghcr.io/o/n:latest' }, /pinned by digest/);
  no({ kind: 'go', module: 'not a module', version: 'v1.0.0' }, /Go package path/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', env: { PATH: '/x' } }, /not a name a target may set/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', env: { NODE_OPTIONS: '--require /x' } }, /not a name a target may set/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', env: { HTTPS_PROXY: 'http://x' } }, /not a name a target may set/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', env: { A: 1 } }, /must be null/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', transport: 'http' }, /http is required/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', transport: 'http', http: { port: 80, path: '/mcp' } }, /port/);
  no({ kind: 'npm', package: 'pkg', version: '1.0.0', args: ['a\nb'] }, /list of at most/);
});

test('a list refuses a wrong format, a repeated id (by number) and a reused dropped id', () => {
  validateList(list([base(), base({ id: 's002' })]));
  assert.throws(() => validateList({ format: 'isokron-corpus-targets/2', targets: [] }), /format/);
  assert.throws(() => validateList(list([base(), base({ id: 's0001' })])), /used twice/);
  assert.throws(() => validateList(list([base({ id: 's002' })], { dropped: [{ id: 's002', reason: 'archived' }] })), /used twice \(or is a dropped id\)/);
  assert.equal(timeoutOf(base(), { defaults: { timeout_s: 300 } }), 300);
  assert.equal(timeoutOf(base({ timeout_s: 60 }), { defaults: { timeout_s: 300 } }), 60);
});

test('sharding: every target lands in exactly one shard, in id order; --only narrows the pool first', () => {
  const ts = Array.from({ length: 23 }, (_, i) => base({ id: `s${String(100 - i).padStart(3, '0')}` }));
  const shards = [1, 2, 3, 4].map((k) => shardTargets(ts, k, 4).map((t) => t.id));
  assert.equal(new Set(shards.flat()).size, 23);
  assert.equal(shards.flat().length, 23);
  assert.equal(shards[0][0], 's078');
  assert.deepEqual(shardTargets(ts, 1, 2, ['s100', 's0099', 's098']).map((t) => t.id), ['s098', 's100']);
  assert.deepEqual(shardTargets(ts, 2, 2, ['s100', 's0099', 's098']).map((t) => t.id), ['s099']);
});

test('launch plans: install with scripts off, run without npx or a shell, lock file named', () => {
  const npm = launchPlan({ kind: 'npm', package: '@s/p', version: '1.0.0', args: ['stdio'] });
  assert.equal(npm.image, 'node24');
  assert.deepEqual(npm.registries, ['registry.npmjs.org']);
  assert.ok(npm.install[0].cmd.includes('--ignore-scripts') && npm.install[0].cmd.includes('@s/p@1.0.0'));
  assert.deepEqual(npm.run({ script: '/work/pkg/node_modules/@s/p/dist/index.js' }), ['node', '/work/pkg/node_modules/@s/p/dist/index.js', 'stdio']);
  assert.ok(!launchPlan({ kind: 'npm', package: 'p', version: '1.0.0', install_scripts: true }).install[0].cmd.includes('--ignore-scripts'));
  assert.equal(launchPlan({ kind: 'npm', package: 'p', version: '1.0.0', node: '22' }).image, 'node22');
  const py = launchPlan({ kind: 'pypi', package: 'mcp-x', version: '1.2', entry: 'mcp-x-server' });
  assert.equal(py.image, 'python');
  assert.ok(py.install[1].cmd.includes('mcp-x==1.2'));
  assert.deepEqual(py.run(), ['/work/venv/bin/mcp-x-server']);
  assert.equal(py.locks[0].name, 'freeze.txt');
  const go = launchPlan({ kind: 'go', module: 'github.com/o/n/cmd/srv', version: 'v1.0.0' });
  assert.deepEqual([go.image, go.runImage], ['go', 'node24']);
  assert.equal(go.install[0].env.CGO_ENABLED, '0');
  assert.deepEqual(go.run(), ['/work/bin/srv']);
  const dk = launchPlan({ kind: 'docker', image: `x/y@sha256:${'a'.repeat(64)}`, args: ['--stdio'] });
  assert.deepEqual([dk.install.length, dk.targetImage.startsWith('x/y@sha256:'), dk.run()], [0, true, ['--stdio']]);
});
