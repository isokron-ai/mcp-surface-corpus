import test from 'node:test';
import assert from 'node:assert/strict';
import { Docker, sandboxRunArgs, helperRunArgs, volumeMount, dockerEnvFrom, checkPinned, checkDockerVersion, HarnessError, SANDBOX_USER, run, tailLine, STDERR_TAIL, isPublicIp4 } from '../src/docker.mjs';
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
  assert.equal(pair(a, '--pids-limit'), '2048');
  assert.ok(a.join(' ').includes('--ulimit nproc=512:512'), 'the process limit gVisor enforces inside the sandbox');
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

test('a helper container: same box, no network unless named, CHOWN or NET_BIND_SERVICE the only capabilities it may be given', () => {
  const a = helperRunArgs({ name: 'surface-x-h1', image: IMG, cmd: ['node', 'static.mjs'], stdin: true });
  assert.equal(pair(a, '--network'), 'none');
  assert.equal(pair(a, '--cap-drop'), 'ALL');
  assert.equal(pair(a, '--user'), '65534:65534');
  assert.ok(a.includes('--read-only') && !a.includes('--cap-add'));
  assert.deepEqual(helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['CHOWN'], user: '0:0' }).filter((x, i, l) => l[i - 1] === '--cap-add'), ['CHOWN']);
  assert.deepEqual(helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['NET_BIND_SERVICE'], user: '0:0' }).filter((x, i, l) => l[i - 1] === '--cap-add'), ['NET_BIND_SERVICE']);
  assert.throws(() => helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['SYS_ADMIN'] }), /CHOWN or NET_BIND_SERVICE only/);
  assert.throws(() => helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], capAdd: ['NET_RAW'] }), /CHOWN or NET_BIND_SERVICE only/);
});

test('gVisor everywhere: every sandbox container gets --runtime runsc, with no way to ask for another', () => {
  assert.equal(pair(sb(), '--runtime'), 'runsc');
  assert.equal(sb().filter((x) => x === '--runtime').length, 1);
  assert.equal(pair(sb({ runtime: 'runc' }), '--runtime'), 'runsc', 'an option to change it is ignored, not honoured');
  // Helpers (our code reading target data) run under gVisor too, the egress proxy included: no
  // helper may name runc.
  assert.equal(pair(helperRunArgs({ name: 'h', image: IMG, cmd: ['true'] }), '--runtime'), 'runsc');
  for (const runtime of ['runc', '', 'kata', 'io.containerd.runc.v2', 'runsc --debug']) assert.throws(() => helperRunArgs({ name: 'h', image: IMG, cmd: ['true'], runtime }), /runtime/);
});

test('a sandbox container runs as 65534 (nobody) with a pid, memory and CPU limit and a small /tmp', () => {
  assert.equal(SANDBOX_USER, '65534:65534');
  const a = sb();
  assert.equal(pair(a, '--user'), '65534:65534');
  assert.match(pair(a, '--tmpfs'), /^\/tmp:rw,nosuid,nodev,exec,size=512m,mode=1777$/);
  assert.equal(pair(a, '--cpus'), '2');
});

test('on a sandbox network: a fixed address, our resolv.conf read-only, and that file is the only bind mount there is', () => {
  const a = sb({ network: 'surface-x-s001-run', ip: '10.213.53.3', resolv: 'run', cidfile: '/tmp/x/cid' });
  assert.equal(pair(a, '--ip'), '10.213.53.3');
  assert.equal(pair(a, '--cidfile'), '/tmp/x/cid');
  const binds = a.filter((x) => /type=bind/.test(x));
  assert.deepEqual(binds, ['type=bind,src=/etc/isokron-sandbox/resolv-run.conf,dst=/etc/resolv.conf,readonly']);
  assert.match(pair(sb({ network: 'n', ip: '10.213.54.4', resolv: 'install' }), '--mount'), /resolv-install\.conf,dst=\/etc\/resolv\.conf,readonly$/);
  assert.throws(() => sb({ network: 'n', resolv: '/etc/passwd' }), /resolv/);
  assert.throws(() => sb({ network: 'n', resolv: 'host' }), /resolv/);
  assert.throws(() => sb({ network: 'none', resolv: 'run' }), /resolv/, 'no resolv.conf where there is no network');
  for (const ip of ['172.17.0.2', '10.213.56.3', '10.213.53.3; rm', '::1']) assert.throws(() => sb({ network: 'n', ip }), /address/, ip);
  assert.throws(() => sb({ network: 'none', ip: '10.213.53.3' }), /address/);
  assert.throws(() => sb({ cidfile: 'relative/cid' }), /cidfile/);
});

test('a helper may name another sandbox container by a fixed host entry (no DNS needed), nothing else', () => {
  const a = helperRunArgs({ name: 'h', image: IMG, network: 'surface-x-s001-run', ip: '10.213.53.4', resolv: 'run', hosts: [['server', '10.213.53.3']], cmd: ['true'] });
  assert.equal(pair(a, '--add-host'), 'server:10.213.53.3');
  assert.equal(a.filter((x) => x === '--add-host').length, 1);
  assert.ok(!helperRunArgs({ name: 'h', image: IMG, cmd: ['true'] }).includes('--add-host'));
  for (const h of [['server', '172.17.0.1'], ['server', 'host-gateway'], ['a b', '10.213.53.3'], ['registry.npmjs.org', '10.213.53.3']]) {
    assert.throws(() => helperRunArgs({ name: 'h', image: IMG, network: 'n', hosts: [h], cmd: ['true'] }), /address|host name/, h.join(' '));
  }
  assert.throws(() => helperRunArgs({ name: 'h', image: IMG, network: 'none', hosts: [['server', '10.213.53.3']], cmd: ['true'] }), /address/);
});

test('the target environment: no runner, Actions or token variable by name, and no value the host holds as a secret', () => {
  for (const k of ['GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'RUNNER_TEMP', 'CORPUS_TARGETS_KEY', 'DOCKER_HOST', 'LD_PRELOAD', 'SSH_AUTH_SOCK', 'github_token']) assert.throws(() => sb({ env: { [k]: 'x' } }), /environment/, k);
  assert.throws(() => sb({ env: { 'A B': 'x' } }), /environment/);
  assert.throws(() => sb({ env: { X: 'a\nb' } }), /environment/);
  const hostEnv = { GH_TOKEN: 'ghs_realtokenvalue1234567890', PATH: '/usr/bin' };
  assert.throws(() => sb({ env: { API_KEY: 'ghs_realtokenvalue1234567890' }, hostEnv }), /environment/);
  assert.throws(() => sb({ env: { URL: 'https://x/?t=ghs_realtokenvalue1234567890' }, hostEnv }), /environment/);
  const ok = sb({ env: { HOME: '/tmp/home', API_KEY: 'surface-dummy-not-a-credential', SURFACE_SANDBOX: '1', PATH_EXTRA: '/usr/bin' }, hostEnv });
  assert.ok(ok.includes('API_KEY=surface-dummy-not-a-credential'));
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

test('a failed harness step says why: the tail of its stderr, bounded and printable', async () => {
  const r = await run(process.execPath, ['-e', `process.stderr.write("a".repeat(5000) + "\\nchmod: changing permissions of '/work': Operation not permitted\\n"); process.exit(1)`]);
  assert.equal(r.exit, 1);
  assert.ok(r.stderr_tail.length <= STDERR_TAIL);
  const dk = new Docker({ runId: 'r1', env: {} });
  await assert.rejects(dk.must(Promise.resolve(r), 'work volume'), (e) => e instanceof HarnessError && /^work volume failed \(exit 1\): \.\.\.a+ \| chmod: changing permissions of '\/work': Operation not permitted$/.test(e.message) && e.message.length < 460);
  assert.equal(tailLine(Buffer.from('x\u001b[31my\r\n\n z\u0000 ')), 'x?[31my | z?');
  await assert.rejects(dk.must(Promise.resolve({ exit: 2, stderr_tail: Buffer.alloc(0) }), 'volume create'), (e) => e.message === 'volume create failed (exit 2)');
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

test('names stay unique across a per-target view of the session (Object.create shares the counter)', () => {
  const dk = new Docker({ runId: 'r1', env: {} });
  const view = Object.create(dk); view.log = '/dev/null';
  const names = [dk.name('s001', 'h'), view.name('s001', 'h'), dk.name('s001', 'h'), view.name('s001', 'h')];
  assert.equal(new Set(names).size, 4);
});

test('the egress proxy gets registry names as fixed host entries: DNS names, public IPv4 addresses only', () => {
  const a = helperRunArgs({ name: 'p', image: IMG, network: 'surface-x-out', create: true, cmd: ['node', 'egress-proxy.mjs'], publicHosts: [['registry.npmjs.org', '104.16.1.34']] });
  assert.equal(a[0], 'create');
  assert.ok(!a.includes('--rm') && !a.includes('--detach'));
  assert.equal(pair(a, '--runtime'), 'runsc');
  assert.equal(pair(a, '--add-host'), 'registry.npmjs.org:104.16.1.34');
  for (const ip of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '172.17.0.1', '192.168.1.1', '100.64.0.1', '10.213.53.2', '0.0.0.0', '224.0.0.1', '1.2.3', '::1', '2606:4700::1111']) {
    assert.equal(isPublicIp4(ip), false, ip);
    assert.throws(() => helperRunArgs({ name: 'p', image: IMG, cmd: ['x'], publicHosts: [['registry.npmjs.org', ip]] }), /public IPv4/, ip);
  }
  for (const n of ['host.docker.internal:1', 'localhost', 'a b.org', '-x.org', 'Registry.npmjs.org']) assert.throws(() => helperRunArgs({ name: 'p', image: IMG, cmd: ['x'], publicHosts: [[n, '104.16.1.34']] }), /DNS name/, n);
  assert.equal(isPublicIp4('104.16.1.34'), true);
});
