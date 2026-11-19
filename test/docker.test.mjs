import test from 'node:test';
import assert from 'node:assert/strict';
import { sandboxRunArgs, helperRunArgs, volumeMount, dockerEnvFrom, checkPinned, checkDockerVersion, HarnessError, SANDBOX_USER, run } from '../src/docker.mjs';
import { decide, makeProxy } from '../sandbox/egress-proxy.mjs';
import { connect } from 'node:net';

const IMG = `docker.io/library/node:24-bookworm-slim@sha256:${'d'.repeat(64)}`;
const sb = (o = {}) => sandboxRunArgs({ name: 'surface-x-s001-s1', image: IMG, network: 'none', cmd: ['node', 'x.js'], ...o });
const pair = (a, flag) => a[a.indexOf(flag) + 1];

test('a sandbox container: non-root, no capabilities, read-only root, limits, no host path', () => {
  const a = sb({ mounts: [{ src: 'surface-x-s001-work', dst: '/work', ro: true }], env: { HOME: '/tmp/home' }, stdin: true });
  assert.equal(pair(a, '--user'), SANDBOX_USER);
  assert.equal(pair(a, '--cap-drop'), 'ALL');
  assert.ok(!a.includes('--cap-add') && !a.includes('--privileged'));
  assert.equal(pair(a, '--security-opt'), 'no-new-privileges');
  assert.ok(a.includes('--read-only') && a.includes('--init') && a.includes('--rm') && a.includes('--interactive'));
  assert.equal(pair(a, '--memory'), '2g');
  assert.equal(pair(a, '--memory-swap'), '2g');
  assert.equal(pair(a, '--pids-limit'), '512');
  assert.equal(pair(a, '--network'), 'none');
  assert.equal(pair(a, '--mount'), 'type=volume,src=surface-x-s001-work,dst=/work,readonly');
  assert.ok(!a.some((x) => /type=bind|docker\.sock|^-v$|--volume/.test(x)));
  assert.deepEqual(a.slice(-3), [IMG, 'node', 'x.js']);
});

test('a sandbox container never gets the host network, the default bridge or an unpinned image', () => {
  for (const network of ['host', 'bridge', 'container:abc', '']) assert.throws(() => sb({ network }), HarnessError);
  assert.throws(() => sb({ image: 'node:24' }), /not pinned by digest/);
  assert.throws(() => sb({ image: 'node@sha256:abc' }), /not pinned by digest/);
  assert.throws(() => volumeMount({ src: '/home/runner/work', dst: '/work' }), /only surface volumes/);
  assert.throws(() => volumeMount({ src: '/var/run/docker.sock', dst: '/var/run/docker.sock' }), /only surface volumes/);
  assert.throws(() => volumeMount({ src: 'surface-x', dst: 'relative' }), /bad mount path/);
  assert.equal(checkPinned(IMG), IMG);
});

test('a helper container: same box, no network unless named, CHOWN the only capability it may be given', () => {
  const a = helperRunArgs({ name: 'surface-x-h1', image: IMG, cmd: ['node', 'static.mjs'], stdin: true });
  assert.equal(pair(a, '--network'), 'none');
  assert.equal(pair(a, '--cap-drop'), 'ALL');
  assert.ok(a.includes('--read-only') && !a.includes('--cap-add'));
  assert.deepEqual(helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['CHOWN'], user: '0:0' }).filter((x, i, l) => l[i - 1] === '--cap-add'), ['CHOWN']);
  assert.throws(() => helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['SYS_ADMIN'] }), /CHOWN only/);
});

test('the docker client gets no token, no key and no GitHub variable from the job', () => {
  const env = dockerEnvFrom({ PATH: '/usr/bin', HOME: '/home/runner', GITHUB_TOKEN: 'ghs_x', GH_TOKEN: 'ghs_x', CORPUS_TARGETS_KEY: 'AGE-SECRET-KEY-1X', ACTIONS_RUNTIME_TOKEN: 'x', RUNNER_TEMP: '/tmp', DOCKER_HOST: 'unix:///var/run/docker.sock' });
  assert.deepEqual(Object.keys(env).sort(), ['DOCKER_HOST', 'HOME', 'PATH']);
});

test('Docker Engine before 26.0.0 is refused (internal networks leaked DNS)', () => {
  checkDockerVersion('26.0.0'); checkDockerVersion('29.9.3');
  assert.throws(() => checkDockerVersion('25.0.5'), /26\.0\.0 or later/);
  assert.throws(() => checkDockerVersion('weird'), /could not be read/);
});

test('run(): keeps stdout up to the cap, kills at the deadline', async () => {
  const r = await run(process.execPath, ['-e', 'process.stdout.write("x".repeat(5000))'], { keepStdout: true, cap: 1000 });
  assert.deepEqual([r.exit, r.stdout_bytes, r.stdout_truncated], [0, 5000, true]);
  const t = await run(process.execPath, ['-e', 'setTimeout(()=>{}, 60000)'], { deadline: Date.now() + 300 });
  assert.equal(t.timed_out, true);
  assert.ok(t.ms < 5000);
});

test('egress proxy: only CONNECT to an allowlisted host name on port 443', async () => {
  const allow = new Set(['registry.npmjs.org']);
  assert.equal(decide('registry.npmjs.org:443', allow).ok, true);
  assert.equal(decide('REGISTRY.NPMJS.ORG.:443', allow).ok, true);
  for (const t of ['evil.example:443', 'registry.npmjs.org:80', 'registry.npmjs.org:22', '169.254.169.254:443', '10.0.0.1:443', 'registry.npmjs.org.evil.example:443', 'registry.npmjs.org', '[::1]:443', 'a b:443']) assert.equal(decide(t, allow).ok, false, t);
  const log = [];
  const server = makeProxy(allow, (o) => log.push(o));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const ask = (req) => new Promise((res) => { const s = connect(port, '127.0.0.1', () => s.write(req)); let b = ''; s.on('data', (c) => { b += c; }); s.on('close', () => res(b)); s.on('error', () => res(b)); });
  assert.match(await ask('CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n'), /^HTTP\/1\.1 403/);
  assert.match(await ask('CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n'), /^HTTP\/1\.1 403/);
  assert.match(await ask('GET http://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n'), /^HTTP\/1\.1 403/);
  server.close();
  assert.deepEqual(log.map((l) => l.allowed), [false, false, false]);
  assert.equal(log[0].host, 'evil.example');
  assert.equal(log[1].error, 'IP literal');
});
