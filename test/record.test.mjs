import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRow, buildState, resolveSdk, vocab, licence } from '../src/record.mjs';
import { sdkFromFile, minor, SDKS } from '../src/sdk.mjs';
import { analyse, runEngine } from '../sandbox/analyse.mjs';
import { estimate } from '../src/tokens.mjs';
import { staticVsLive, fingerprint, diffRuns, canonical } from '../src/compare.mjs';
import { toolFeatures, listFeatures } from '../src/features.mjs';

const tool = (name, o = {}) => ({ name, description: `Reads ${name}.`, inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'The id.' } }, required: ['id'] }, ...o });
const page = (tools, extra = {}) => ({ jsonrpc: '2.0', id: 2, result: { tools, ...extra } });

test('SDK versions from lock files, manifests and installed trees, by a fixed table of names', () => {
  const lock = JSON.stringify({ packages: { 'node_modules/@modelcontextprotocol/sdk': { version: '1.21.0' }, 'node_modules/fastmcp': { version: '3.4.1' }, 'node_modules/evil-sdk': { version: '9' } } });
  assert.deepEqual(sdkFromFile('package-lock.json', lock).map((h) => [h.sdk, h.version, h.kind]), [['typescript-sdk', '1.21.0', 'locked'], ['fastmcp-ts', '3.4.1', 'locked']]);
  assert.deepEqual(sdkFromFile('pnpm-lock.yaml', "  '@modelcontextprotocol/sdk@1.20.2':\n    resolution: {}\n").map((h) => h.version), ['1.20.2']);
  assert.deepEqual(sdkFromFile('yarn.lock', '"@modelcontextprotocol/sdk@^1.0.0":\n  version "1.19.0"\n').map((h) => h.version), ['1.19.0']);
  assert.deepEqual(sdkFromFile('uv.lock', '[[package]]\nname = "mcp"\nversion = "1.9.4"\n\n[[package]]\nname = "fastmcp"\nversion = "2.11.0"\n').map((h) => [h.sdk, h.version]), [['python-sdk', '1.9.4'], ['fastmcp-py', '2.11.0']]);
  assert.deepEqual(sdkFromFile('freeze.txt', 'anyio==4.0\nmcp==2.3.0\n').map((h) => [h.sdk, h.version]), [['python-sdk', '2.3.0']]);
  assert.deepEqual(sdkFromFile('requirements.txt', 'mcp[cli]>=1.2\n').map((h) => [h.kind, h.spec]), [['declared', '>=1.2']]);
  assert.deepEqual(sdkFromFile('go.mod', 'require (\n\tgithub.com/mark3labs/mcp-go v0.32.0\n)\n').map((h) => [h.sdk, h.version]), [['mcp-go', '0.32.0']]);
  assert.deepEqual(sdkFromFile('go-version-m.txt', '\tdep\tgithub.com/modelcontextprotocol/go-sdk\tv1.1.0\th1:x\n').map((h) => [h.sdk, h.version, h.kind]), [['go-sdk', '1.1.0', 'installed']]);
  assert.deepEqual(sdkFromFile('Cargo.lock', '[[package]]\nname = "rmcp"\nversion = "0.8.1"\n').map((h) => [h.sdk, h.version]), [['rmcp', '0.8.1']]);
  assert.equal(sdkFromFile('package-lock.json', '{"packages":{"node_modules/@modelcontextprotocol/sdk":{"version":"<script>alert(1)</script>"}}}')[0].version, null, 'a version that is not a version is dropped');
  assert.deepEqual(sdkFromFile('package-lock.json', 'not json'), []);
  assert.equal(minor('2.4.0'), '2.4');
  assert.ok(SDKS.every((s) => /^[a-z0-9-]+$/.test(s[0])));
});

test('the SDK a server runs on: the one its own manifest declares, with the installed version', () => {
  const hits = [
    { sdk: 'typescript-sdk', ecosystem: 'npm', version: '1.32.1', kind: 'installed', depth: -1, source: 'package-lock.json' },
    { sdk: 'typescript-sdk-server', ecosystem: 'npm', version: '2.4.0', kind: 'installed', depth: -1, source: 'package-lock.json' },
    { sdk: 'typescript-sdk-server', ecosystem: 'npm', version: null, kind: 'declared', depth: 0, source: 'package.json' },
  ];
  assert.deepEqual(resolveSdk(hits), { id: 'typescript-sdk-server', ecosystem: 'npm', version: '2.4.0', minor: '2.4', kind: 'installed', source: 'package-lock.json', declared: true });
  assert.equal(resolveSdk([hits[0]]).id, 'typescript-sdk');
  assert.equal(resolveSdk([]), null);
  assert.equal(resolveSdk([{ sdk: 'made-up', version: '1.0.0', kind: 'installed' }]), null, 'a name outside the table is never reported');
});

test('the engine run keeps every check and every finding with its evidence; a list it cannot read is an error, not a crash', () => {
  const r = runEngine([page([tool('get_item'), { name: 'bad name', inputSchema: { type: 'objec' } }])]);
  assert.equal(r.ok, true);
  assert.equal(Object.keys(r.matrix).length, 76);
  assert.equal(r.tool_count, 2);
  assert.ok(r.matrix['spec-name-charset'].findings >= 1 && r.matrix['spec-name-charset'].tools === 1);
  assert.ok(r.report.sections.spec && r.grades.spec.grade);
  const bad = runEngine('{"tools": 5}');
  assert.equal(bad.ok, false);
  assert.ok(bad.error);
});

test('analysis: live and static graded separately, compared per tool and per check; token estimates labelled', () => {
  const live = [tool('get_item', { annotations: { readOnlyHint: true } }), tool('delete_item'), tool('list_items', { outputSchema: { type: 'object' } })];
  const stat = [tool('get_item'), tool('delete_item', { description: 'Different.' }), tool('ghost_tool')];
  const a = analyse({ live_pages: [page(live)], static: [{ kind: 'source', fidelity: 'derived', tools: stat }], readme: [{ name: 'get_item' }], registry: null, probe: { lists: { 'tools/list': { ok: true, items: live, pages: 1, ms: 3 }, 'prompts/list': { ok: false, items: [], pages: 0, error_code: -32601 } }, initialize: { capabilities: { tools: { listChanged: true }, prompts: {} } } } });
  assert.deepEqual(Object.keys(a.runs).sort(), ['live', 'readme', 'static_best']);
  assert.equal(a.engine.checks, 76);
  const b = a.static_vs_live.best;
  assert.deepEqual([b.shared, b.only_live, b.only_static], [2, ['list_items'], ['ghost_tool']]);
  assert.equal(b.name_jaccard, 0.5);
  assert.deepEqual([b.agree.description, b.agree.inputSchema, b.agree.annotations], [1, 2, 1]);
  assert.ok(Object.values(a.static_vs_live.checks).every((v) => ['both', 'live_only', 'static_only', 'neither'].includes(v)));
  assert.equal(Object.keys(a.static_vs_live.checks).length, 76);
  assert.deepEqual(Object.keys(a.tokens.live).sort(), ['bpe_approx', 'bytes', 'bytes_div_4', 'chars', 'claude_approx', 'per_tool', 'tools_only']);
  assert.equal(a.tokens.live.per_tool.length, 3);
  assert.equal(a.features.live.output_schema, 1);
  assert.equal(a.features.live.annotations.hints.readOnlyHint.set, 1);
  assert.deepEqual(a.list_features.consistency['prompts/list'], { advertised: true, answered: false });
  assert.equal(a.list_features.list_changed.tools, true);
  assert.equal(estimate('abcd'.repeat(100)).bytes_div_4, 100);
});

test('fingerprints: stable under key order; a diff names the parts that changed', () => {
  assert.equal(canonical({ b: 1, a: [2, { d: 1, c: 2 }] }), canonical({ a: [2, { c: 2, d: 1 }], b: 1 }));
  const a = fingerprint([tool('x'), tool('y')]); const b = fingerprint([tool('x', { description: 'New.' }), tool('z')]);
  const d = diffRuns(a, b);
  assert.deepEqual([d.added, d.removed, d.changed, d.any], [['z'], ['y'], [{ name: 'x', parts: ['description'] }], true]);
  assert.equal(diffRuns(a, a).any, false);
  assert.equal(staticVsLive([tool('x')], [tool('x')]).agree.whole, 1);
  assert.equal(toolFeatures([tool('get_item'), tool('getItem'), tool('a.b')]).name_styles.snake, 1);
  assert.equal(listFeatures(null).capabilities.length, 0);
});

test('a row holds numbers, booleans and fixed vocabulary only: nothing a server wrote', () => {
  const EVIL = 'ZZ-EVIL-<img src=x onerror=alert(1)>';
  const tools = [tool('get_item'), tool(`${EVIL}_tool`, { description: EVIL })];
  const probe = {
    era: 'legacy', initialize: { protocolVersion: EVIL, capabilities: { tools: {}, [EVIL]: {} }, serverInfo: { name: EVIL, version: EVIL, title: EVIL }, instructions: EVIL },
    lists: { 'tools/list': { ok: true, items: tools, pages: 1, raw_pages: [page(tools)], ms: 2 } },
    timing: { initialize_ms: 900, tools_ms: 950, total_ms: 990 }, stderr_bytes: 10, transport: { non_json_lines: 0, notifications: [EVIL], server_requests: [EVIL, 'roots/list'], exit: 0 },
  };
  const analysis = analyse({ live_pages: probe.lists['tools/list'].raw_pages, static: [], readme: null, registry: null, probe: { lists: { 'tools/list': { ok: true, items: tools, pages: 1 } }, initialize: probe.initialize } });
  const stat = { primary_language: 'typescript', static: { best: null, candidates: [] }, readme: null, sdk: { hits: [] }, license_files: [{ spdx_guess: 'MIT' }], manifests: [], server_json: [] };
  const row = buildRow({ id: 's007', publicExit: 0, launch: { kind: 'npm' }, facts: { pinned: true, repo: { stars: 5, forks: 0, archived: false, fork: false, license_spdx: EVIL, pushed_at: '2026-11-01T00:00:00Z' }, commit: { date: '2026-11-01T00:00:00Z' } }, registry: null, stat, bare: probe, withEnv: null, primary: probe, analysis, envNames: { list: [], readme: [EVIL], source: ['X_TOKEN'], used: [] }, lockHits: [{ sdk: EVIL, version: '1.0.0', kind: 'installed' }], timing: {}, baselineMs: 600, now: '2026-11-11T00:00:00Z' });
  const text = JSON.stringify(row);
  assert.ok(!text.includes('ZZ-EVIL') && !text.includes('onerror'), 'no server text in the row');
  assert.equal(row.live.protocol_version, 'other');
  assert.deepEqual(row.live.capabilities, ['other', 'tools']);
  assert.deepEqual(row.live.server_requests, ['roots/list']);
  assert.equal(row.repo.licence, 'other');
  assert.equal(row.repo.commit_age_days, 10);
  assert.equal(row.sdk, null);
  assert.equal(row.live.startup_ms, 300);
  assert.equal(row.env.source_secret_named, 1);
  assert.equal(row.acquired, 'live');
  assert.deepEqual([vocab(new Set(['a']), 'a'), vocab(new Set(['a']), 'b'), vocab(new Set(['a']), null)], ['a', 'other', null]);
  assert.deepEqual([licence('GPL-3.0-only'), licence('WTFPL'), licence(null)], ['GPL-3.0', 'other', null]);
  // The state (private) does keep tool names: it is what the next run is compared with.
  const state = buildState({ id: 's007', row, analysis, sha: 'a'.repeat(40), resolved: '1.0.0' });
  assert.deepEqual([state.acquired, state.tools.length, state.commit.length, state.package_version], ['live', 2, 40, '1.0.0']);
  assert.ok(state.checks.length > 0 && state.grades.spec);
});

test('a row for a server that never started still records the static layer and why live failed', () => {
  const stat = { primary_language: 'python', static: { best: { kind: 'source', fidelity: 'derived', tools: 1 }, candidates: [{ kind: 'source', fidelity: 'derived', tools: [tool('a')] }] }, readme: { tools: [{ tool: { name: 'a' } }] }, sdk: { hits: [{ sdk: 'python-sdk', ecosystem: 'pypi', version: '1.9.0', kind: 'locked', depth: 0, source: 'uv.lock' }] }, license_files: [], manifests: [{ path: 'uv.lock' }], server_json: [] };
  const analysis = analyse({ live_pages: null, static: stat.static.candidates, readme: [{ name: 'a' }], registry: null, probe: null });
  const dead = { era: null, error: 'the server exited', initialize: null, lists: {}, transport: { exit: 1 } };
  const row = buildRow({ id: 's008', publicExit: 0, launch: { kind: 'pypi' }, facts: { pinned: false }, registry: { found: true, tools: null, packages: [{}], remotes: [], env: [{ name: 'K', required: true, secret: true }] }, stat, bare: dead, withEnv: dead, primary: null, analysis, envNames: { list: [], registry: ['K'], readme: [], source: [], used: ['API_KEY'] }, lockHits: [], timing: {}, baselineMs: 600 });
  assert.equal(row.acquired, 'static');
  assert.equal(row.live, null);
  assert.deepEqual([row.layers.live.attempted, row.layers.live.ok, row.layers.live.bare.error, row.layers.live.with_env.exit], [true, false, 'transport', 1]);
  assert.deepEqual([row.layers.registry.found, row.env.registry_required, row.env.registry_secret, row.env.secret_named], [true, 1, 1, 1]);
  assert.equal(row.size.from, 'static');
  assert.deepEqual([row.sdk.id, row.sdk.version, row.sdk.kind], ['python-sdk', '1.9.0', 'locked']);
  assert.ok(row.checks.static && !row.checks.live);
  assert.equal(row.repo.has_lockfile, true);
});

test('the engine run records the severity each check\'s findings carried: a live answer without 2026-07-28 fields is advice, one with some of them is attention', () => {
  const legacy = runEngine([page([tool('get_item')])]);
  assert.deepEqual([legacy.matrix['spec-envelope-result-type'].sev, legacy.matrix['spec-envelope-cache'].sev], ['advice', 'advice']);
  const next = runEngine([page([tool('get_item')], { ttlMs: 1000, cacheScope: 'private' })]);
  assert.equal(next.matrix['spec-envelope-result-type'].sev, 'attention');
  assert.equal(legacy.matrix['spec-name-charset'].sev, null, 'no finding, no severity');
});
