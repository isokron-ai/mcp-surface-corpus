import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fakeFetch, tarGz } from './helpers.mjs';
import { githubFacts, registryEntry, sourceArchive } from '../src/sources.mjs';

process.env.SURFACE_PROBE_MS = '6000';
const D = await import('../bin/run-shard.mjs');
const SHA = 'c'.repeat(40);

test('driver options: shard bounds, id shape, no unknown flags', () => {
  const o = D.parseArgs(['--targets', 't.json', '--out', 'o', '--shard', '2', '--shards', '4', '--only', 's001,s002', '--lane', 'ci']);
  assert.deepEqual([o.shard, o.shards, o.only, o.lane], [2, 4, ['s001', 's002'], 'ci']);
  assert.throws(() => D.parseArgs(['--targets', 't', '--out', 'o', '--shard', '5', '--shards', '4']), /--shard must be/);
  assert.throws(() => D.parseArgs(['--targets', 't', '--out', 'o', '--only', 'evil;rm']), /target ids/);
  assert.throws(() => D.parseArgs(['--targets', 't', '--out', 'o', '--privileged']), /unknown option/);
  assert.throws(() => D.parseArgs(['--out', 'o']), /usage/);
});

test('images.json: every image pinned by digest; a mirror changes the host, never the digest', () => {
  const f = new URL('../images.json', import.meta.url).pathname;
  const a = D.loadImages(f, '');
  assert.deepEqual(Object.keys(a), ['node24', 'node22', 'python', 'go']);
  assert.ok(Object.values(a).every((r) => /^docker\.io\/library\/[a-z]+:[a-z0-9.-]+@sha256:[0-9a-f]{64}$/.test(r)));
  const b = D.loadImages(f, 'mirror.gcr.io');
  assert.ok(Object.keys(a).every((k) => b[k] === a[k].replace('docker.io/', 'mirror.gcr.io/')));
  assert.throws(() => D.loadImages(f, 'evil.example/x y'), /not a host name/);
});

test('the env a probe sets: names from the list, the registry (required) and the README (secret-named only); values are dummies', () => {
  const p = D.envPlan({ env: { API_KEY: null, REGION: 'eu-west-1' } }, { env: [{ name: 'ORG_ID', required: true }, { name: 'OPTIONAL_X', required: false }] }, { env_refs: { readme: ['SERVICE_API_KEY', 'SERVICE_URL', 'LOG_LEVEL', 'DATA_PATH', 'FEATURE_ENABLED', 'PATH', 'NODE_OPTIONS', 'GITHUB_TOKEN'], source: ['DEBUG_X'] } });
  assert.deepEqual(p.names.used, ['API_KEY', 'REGION', 'ORG_ID', 'SERVICE_API_KEY']);
  assert.deepEqual(p.env, { API_KEY: 'surface-dummy-not-a-credential', REGION: 'eu-west-1', ORG_ID: 'surface-dummy-not-a-credential', SERVICE_API_KEY: 'surface-dummy-not-a-credential' });
  assert.deepEqual(p.names.readme.slice(0, 5), ['SERVICE_API_KEY', 'SERVICE_URL', 'LOG_LEVEL', 'DATA_PATH', 'FEATURE_ENABLED']);
  assert.deepEqual(p.names.source, ['DEBUG_X']);
  assert.deepEqual(D.envPlan(null, null, null).names.used, []);
});

test('the per-run order of the public lines is a shuffle of the shard, the same for the same run id', () => {
  const ids = Array.from({ length: 20 }, (_, i) => i);
  const a = D.shuffled(ids, 'a1b2c3d4e5f60718'); const b = D.shuffled(ids, 'a1b2c3d4e5f60718'); const c = D.shuffled(ids, '0718a1b2c3d4e5f6');
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, ids);
  assert.notDeepEqual(a, c);
  assert.deepEqual([...a].sort((x, y) => x - y), ids);
});

test('host-side fetches: fixed hosts, the token to api.github.com only, facts mapped to numbers and a fixed shape', async () => {
  const f = fakeFetch({ archives: { [SHA]: tarGz({ 'a.txt': 'x' }) }, registry: { servers: [{ server: { name: 'io.github.o/n', version: '1.0.0', packages: [{ registryType: 'npm', identifier: 'n', version: '1.0.0', transport: { type: 'stdio' }, environmentVariables: [{ name: 'N_API_KEY', isRequired: true, isSecret: true }] }], remotes: [{ type: 'streamable-http', url: 'https://x/{id}/mcp' }] } }] } });
  const facts = await githubFacts({ repo: 'o/n', commit: SHA }, { fetchFn: f, token: 'tok' });
  assert.deepEqual([facts.ok, facts.sha, facts.pinned, facts.repo.stars, facts.repo.license_spdx, facts.repo.has_mcp_topic, facts.commit.date], [true, SHA, true, 1234, 'MIT', true, '2026-11-01T00:00:00Z']);
  const followed = await githubFacts({ repo: 'o/n', ref: 'main' }, { fetchFn: f });
  assert.deepEqual([followed.sha, followed.pinned], ['b'.repeat(40), false]);
  const a = await sourceArchive('o/n', SHA, { fetchFn: f });
  assert.equal(a.via, 'codeload');
  await assert.rejects(sourceArchive('o/n', 'main', { fetchFn: f }), /full commit SHA/);
  const r = await registryEntry('io.github.o/n', { fetchFn: f });
  assert.deepEqual([r.found, r.packages[0].registry_type, r.env[0], r.remotes[0].templated], [true, 'npm', { name: 'N_API_KEY', required: true, secret: true, has_default: false }, true]);
  assert.equal((await registryEntry('io.github.o/missing', { fetchFn: f })).found, false);
  assert.ok(f.calls.filter((c) => c.auth).every((c) => c.url.startsWith('https://api.github.com/')));
  assert.ok(f.calls.some((c) => c.auth));
  const down = await githubFacts({ repo: 'o/n', commit: SHA }, { fetchFn: async () => new Response('no', { status: 403 }) });
  assert.deepEqual([down.ok, down.repo, down.errors.length], [true, null, 2], 'a pinned commit survives an API outage');
});

// ---- The sandbox against a real Docker daemon (SURFACE_DOCKER_TESTS=1; SURFACE_IMAGE_MIRROR for a mirror) ----
const docker = process.env.SURFACE_DOCKER_TESTS === '1';
const INLINE = (tools) => `const need=process.argv[1];if(need&&need!=='-'&&!process.env[need]){console.error(need+' required');process.exit(1)}const T=${tools};let b='';process.stdin.on('data',c=>{b+=c;let i;while((i=b.indexOf('\\n'))>=0){const l=b.slice(0,i);b=b.slice(i+1);if(!l.trim())continue;const m=JSON.parse(l);if(m.id===undefined)continue;Promise.resolve(typeof T==='function'?T():T).then(t=>{const r=m.method==='initialize'?{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'inline',version:'1'}}:m.method==='tools/list'?{tools:t}:null;process.stdout.write(JSON.stringify(r?{jsonrpc:'2.0',id:m.id,result:r}:{jsonrpc:'2.0',id:m.id,error:{code:-32601,message:'no'}})+'\\n')})}})`;
const TOOL = (n) => `{name:'${n}',description:'Gets a thing.',inputSchema:{type:'object',properties:{id:{type:'string'}}}}`;
const HTTP = `const T=[${TOOL('get_thing')}];require('http').createServer((q,s)=>{let b='';q.on('data',c=>b+=c);q.on('end',()=>{const m=JSON.parse(b);if(m.id===undefined){s.writeHead(202).end();return}const r=m.method==='initialize'?{protocolVersion:'2025-11-25',capabilities:{tools:{}},serverInfo:{name:'inline-http',version:'1'}}:m.method==='tools/list'?{tools:T}:null;s.writeHead(200,{'content-type':'application/json'});s.end(JSON.stringify(r?{jsonrpc:'2.0',id:m.id,result:r}:{jsonrpc:'2.0',id:m.id,error:{code:-32601,message:'no'}}))})}).listen(8123,'0.0.0.0')`;
// Reports through its tool name whether it could reach the outside or the host from inside the sandbox.
const NET = `async()=>{const tryIt=async(u)=>{try{await fetch(u,{signal:AbortSignal.timeout(1500)});return true}catch{return false}};const out=await tryIt('https://registry.npmjs.org/-/ping')||await tryIt('http://169.254.169.254/')||await tryIt('http://host.docker.internal/');let w='ro';try{require('fs').writeFileSync('/etc/x','x');w='rw'}catch{}return[{name:(out?'net_open':'net_blocked')+'_root_'+w+'_uid_'+process.getuid(),description:'Probe.',inputSchema:{type:'object'}}]}`;

test('sandbox, end to end: stdio, a server that needs an env value, http, static only, no network, a hang', { skip: !docker && 'set SURFACE_DOCKER_TESTS=1 (needs Docker)' }, async () => {
  const images = D.loadImages(new URL('../images.json', import.meta.url).pathname);
  const image = images.node24;
  const d = mkdtempSync(join(tmpdir(), 'surface-drv-'));
  const dk = (code, extra = {}, arg = '-') => ({ kind: 'docker', image, entrypoint: 'node', args: ['-e', code, arg], ...extra });
  const t = (n, o) => ({ id: `s00${n}`, repo: 'o/n', commit: SHA, ...o });
  const list = { format: 'isokron-surface-targets/1', defaults: { timeout_s: 120 }, targets: [
    t(1, { launch: dk(INLINE(`[${TOOL('get_thing')},${TOOL('live_only_tool')}]`)) }),
    t(2, { launch: dk(INLINE(`[${TOOL('get_thing')}]`), { env: { THING_API_KEY: null } }, 'THING_API_KEY') }),
    t(3, { launch: { kind: 'docker', image, entrypoint: 'node', args: ['-e', HTTP], transport: 'http', http: { port: 8123, path: '/mcp' } } }),
    t(4, {}),
    t(5, { launch: dk(INLINE(NET)) }),
    t(6, { launch: dk('setInterval(()=>{},1000)') }),
  ] };
  writeFileSync(join(d, 'targets.json'), JSON.stringify(list));
  const src = tarGz({ 'src/index.ts': 'server.registerTool("get_thing", { description: "Gets a thing.", inputSchema: { id: z.string() } }, async () => ({ content: [] }));\nserver.registerTool("static_only_tool", { description: "Gone.", inputSchema: {} }, async () => ({ content: [] }));', 'package.json': '{"name":"n","dependencies":{"@modelcontextprotocol/sdk":"^1.20.0"}}', 'README.md': '# n\n\n## Tools\n\n- `get_thing` - Gets a thing\n', LICENSE: 'MIT License' }, { commit: SHA });
  const out = join(d, 'out');
  const lines = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (s, ...r) => { if (typeof s === 'string' && /^(run finished|surface corpus)/.test(s)) { lines.push(s.trim()); return true; } return write(s, ...r); };
  let rc;
  try { rc = await D.main(['--targets', join(d, 'targets.json'), '--consume-targets', '--out', out], { fetchFn: fakeFetch({ archives: { '*': src } }) }); } finally { process.stdout.write = write; }
  assert.equal(rc, 0);
  assert.equal(existsSync(join(d, 'targets.json')), false, 'the clear-text list is deleted before any target runs');
  assert.deepEqual(lines.filter((l) => l.startsWith('run finished')), Array(6).fill('run finished, exit 0'), 'the public lines carry no id and no verdict');
  const rows = Object.fromEntries(readFileSync(join(out, '_shard', 'rows.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).map((r) => [r.id, r]));
  // s001: starts bare; static and live disagree in a known way. On a failure, say why: the record's errors.
  const why = (id) => JSON.stringify(JSON.parse(readFileSync(join(out, id, 'record.json'), 'utf8')).errors);
  assert.ok(rows.s001.live, `s001 has no live result: ${why('s001')}`);
  assert.deepEqual([rows.s001.acquired, rows.s001.live.starts_without_env, rows.s001.size.tools], ['live', true, 2]);
  assert.deepEqual([rows.s001.static_vs_live.shared, rows.s001.static_vs_live.only_live, rows.s001.static_vs_live.only_static], [1, 1, 1]);
  assert.deepEqual([rows.s001.repo.stars, rows.s001.repo.licence, rows.s001.sdk.id, rows.s001.sdk.kind], [1234, 'MIT', 'typescript-sdk', 'declared']);
  // s002: does not start bare, starts with a dummy value.
  assert.deepEqual([rows.s002.live.starts_without_env, rows.s002.live.starts_with_dummy_env, rows.s002.layers.live.primary, rows.s002.env.secret_named], [false, true, 'with_env', 1]);
  const rec2 = JSON.parse(readFileSync(join(out, 's002', 'record.json'), 'utf8'));
  assert.deepEqual(rec2.env.names.used, ['THING_API_KEY']);
  assert.match(JSON.parse(readFileSync(join(out, 's002', 'probe-bare.json'), 'utf8')).stderr, /THING_API_KEY required/);
  // s003: streamable HTTP on an internal network.
  assert.deepEqual([rows.s003.acquired, rows.s003.layers.live.transport, rows.s003.size.tools], ['live', 'http', 1]);
  // s004: no launch block: static and README only.
  assert.deepEqual([rows.s004.acquired, rows.s004.layers.live.attempted, rows.s004.layers.static.tools, rows.s004.layers.readme.tools], ['static', false, 2, 1]);
  // s005: inside the sandbox there is no way out, the root is read-only, and the user is not root.
  const p5 = JSON.parse(readFileSync(join(out, 's005', 'probe-bare.json'), 'utf8'));
  assert.ok(p5.lists && p5.lists['tools/list'] && p5.lists['tools/list'].items && p5.lists['tools/list'].items[0], `s005 listed no tool: ${JSON.stringify({ error: p5.error, lists: p5.lists, timing: p5.timing, transport: p5.transport, stderr: p5.stderr }).slice(0, 1500)}; ${why('s005')}`);
  assert.equal(p5.lists['tools/list'].items[0].name, 'net_blocked_root_ro_uid_65534');
  // s006: a server that never answers is stopped; it is data, not a harness error.
  assert.deepEqual([rows.s006.public_exit, rows.s006.layers.live.ok, rows.s006.acquired], [0, false, 'static']);
  // Every raw piece is kept per target.
  assert.deepEqual(readdirSync(join(out, 's001')).sort(), ['analysis.json', 'probe-bare.json', 'record.json', 'static.json', 'steps.log']);
  const a1 = JSON.parse(readFileSync(join(out, 's001', 'analysis.json'), 'utf8'));
  assert.equal(Object.keys(a1.runs.live.matrix).length, 76);
  assert.ok(Array.isArray(a1.runs.live.report.tools));
  const shard = JSON.parse(readFileSync(join(out, '_shard', 'shard.json'), 'utf8'));
  assert.equal(shard.engine.rubric_version, '2.1.0');
  assert.ok(shard.baseline_initialize_ms > 0);
  // Nothing outlives the run.
  for (const what of [['ps', '-aq'], ['volume', 'ls', '-q'], ['network', 'ls', '-q']]) assert.equal(execFileSync('docker', [...what, '--filter', `label=${D.LABEL_RUN}=${shard.run}`]).toString().trim(), '');
});
