// The start environment of a target's server (R-SBX-44..49): a review of every recorded live-probe start failure
// (26 Nov 2026) found most were ours. OCI images ran in our /tmp instead of their WORKDIR, wrote to their declared
// VOLUMEs on a read-only root, an arm64 image exited "Exec format error", an HTTP server's error went unread, an npm
// package's CLI bin ran instead of its server bin, and a PyPI server's MCP SDK sat in an extra we did not install.
// Every fix keeps the sandbox's hardening: gVisor, uid 65534, no capabilities, read-only root, limits, no egress.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { HarnessError, LIMITS, SANDBOX_USER, imageConfigOf, imagePath, run, sandboxRunArgs, volumeTmpfs } from '../src/docker.mjs';
import { launchPlan, validateTarget } from '../src/targets.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const IMG = `ghcr.io/acme/srv:1@sha256:${'e'.repeat(64)}`;
const sb = (o = {}) => sandboxRunArgs({ name: 'surface-x-s001-s', image: IMG, network: 'surface-x-s001-run', ip: '10.213.53.3', resolv: 'run', cmd: [], ...o });
const pair = (a, flag) => a[a.indexOf(flag) + 1];
const all = (a, flag) => a.filter((_, i) => a[i - 1] === flag);
const hardened = (a) => {
  assert.equal(pair(a, '--runtime'), 'runsc');
  assert.equal(pair(a, '--user'), SANDBOX_USER);
  assert.equal(pair(a, '--cap-drop'), 'ALL');
  assert.ok(a.includes('--read-only'));
  assert.equal(pair(a, '--memory'), LIMITS.memory);
  assert.equal(pair(a, '--pids-limit'), LIMITS.pids);
  assert.equal(pair(a, '--network'), 'surface-x-s001-run');
  assert.ok(!a.some((x) => /type=bind,src=(?!\/etc\/isokron-sandbox\/)/.test(x)), 'no host path');
};

test('R-SBX-44 an OCI target runs in its image\'s own WORKDIR, read from the pulled image, never one it cannot name plainly', () => {
  // The shape `docker image inspect --format '{{json .Config}} {{.Os}}/{{.Architecture}}'` prints.
  const cfg = imageConfigOf('{"User":"","WorkingDir":"/app","Volumes":{"/data":{},"/app/logs":{}},"Entrypoint":["node","dist/index.js"]} linux/amd64\n');
  assert.deepEqual(cfg, { workdir: '/app', volumes: ['/data', '/app/logs'], platform: 'linux/amd64' });
  assert.deepEqual(imageConfigOf('{"WorkingDir":"","Volumes":null} linux/amd64'), { workdir: null, volumes: [], platform: 'linux/amd64' });
  assert.deepEqual(imageConfigOf(''), { workdir: null, volumes: [], platform: null });
  for (const bad of ['app', '/', '/app/../etc', '/a b', '/x;rm', '/./x', '//']) assert.equal(imagePath(bad), null, bad);
  const a = sb({ workdir: '/app' });
  assert.equal(pair(a, '--workdir'), '/app');
  hardened(a);
  assert.equal(pair(sb(), '--workdir'), '/tmp', 'an image with no WORKDIR, and every npm or PyPI server, keeps /tmp');
  assert.throws(() => sb({ workdir: '/app/../etc' }), HarnessError);
  assert.throws(() => sb({ workdir: 'relative' }), HarnessError);
  // The run step passes it for OCI targets only.
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /const oci = plan\.targetImage && inst\.oci \?/);
  assert.match(src, /probeStdioIn\(ctx, tdk, \{[^}]*\.\.\.oci,/);
  assert.match(src, /sandboxRunArgs\(\{ name, image: runImage,[^}]*\.\.\.oci \}\)/);
});

test('R-SBX-45 a size-capped tmpfs over each VOLUME the image declares, at most eight, never over /tmp or the system folders', () => {
  const a = sb({ workdir: '/app', tmpfs: ['/data', '/config'] });
  const t = all(a, '--tmpfs');
  assert.deepEqual(t, [`/tmp:rw,nosuid,nodev,exec,size=${LIMITS.tmp},mode=1777`, '/data:rw,nosuid,nodev,noexec,size=64m,mode=1777', '/config:rw,nosuid,nodev,noexec,size=64m,mode=1777']);
  hardened(a);
  assert.deepEqual(volumeTmpfs(['/data/', '/data', '/tmp', '/tmp/x', '/proc', '/etc/app', '/dev/shm', 'rel', '/a/../b', 7, '/var/log/supervisor']), ['/data', '/var/log/supervisor']);
  const many = Array.from({ length: 20 }, (_, i) => '/v' + i);
  assert.equal(volumeTmpfs(many).length, LIMITS.volTmpCount);
  assert.equal(LIMITS.volTmpCount, 8);
  assert.equal(LIMITS.volTmp, '64m');
  // sandboxRunArgs never takes a path volumeTmpfs would drop.
  for (const bad of [['/etc'], ['/tmp'], ['rel'], many]) assert.throws(() => sb({ tmpfs: bad }), HarnessError, JSON.stringify(bad).slice(0, 40));
  assert.deepEqual(all(sb(), '--tmpfs').length, 1, 'no image volumes, only /tmp');
});

test('R-SBX-46 a target image is pulled for linux/amd64 only, and its platform is recorded', () => {
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /tdk\.d\(\['pull', '-q', '--platform', 'linux\/amd64', image\]/);
  assert.match(src, /inst\.oci = \{ workdir: ic\.workdir, volumes: volumeTmpfs\(ic\.volumes\), platform: ic\.platform \}/);
  assert.equal(imageConfigOf('{} linux/arm64').platform, 'linux/arm64');
  assert.equal(imageConfigOf('{} linux/arm64;x').platform, null);
});

test('R-SBX-47 an HTTP server\'s own stderr is read back: docker logs writes it to its stderr, which is now kept', async () => {
  const r = await run(process.execPath, ['-e', 'process.stdout.write("out\\n"); process.stderr.write("Error: missing API_KEY\\n")'], { keepStdout: true, keepStderr: true, logStdout: false });
  assert.equal(r.stdout.toString(), 'out\n');
  assert.equal(r.stderr.toString(), 'Error: missing API_KEY\n');
  assert.equal(r.stderr_bytes, 23);
  const r0 = await run(process.execPath, ['-e', 'process.stderr.write("x")'], {});
  assert.equal(r0.stderr, undefined, 'only when asked');
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /tdk\.d\(\['logs', name\], \{ keepStdout: true, keepStderr: true,/);
  assert.match(src, /p\.stderr = Buffer\.concat\(\[logs\.stdout, logs\.stderr \|\| Buffer\.alloc\(0\)\]\)/);
});

test('R-SBX-48 with several bins the npm entry is the one whose name says mcp or server, unless the package\'s own name says so', () => {
  const entry = (pkg, bin, want = '') => {
    const pre = mkdtempSync(join(tmpdir(), 'npm-entry-'));
    const dir = join(pre, 'node_modules', ...pkg.split('/'));
    mkdirSync(dir, { recursive: true });
    for (const f of Object.values(typeof bin === 'string' ? { x: bin } : bin)) writeFileSync(join(dir, f), '');
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: pkg, version: '1.0.0', bin }));
    const r = spawnSync(process.execPath, [join(root, 'sandbox', 'npm-entry.mjs'), pre, pkg, want], { encoding: 'utf8' });
    return JSON.parse(r.stdout).bin;
  };
  // return_rp ships return_rp (its CLI) and return_rp-mcp.
  assert.equal(entry('return_rp', { return_rp: 'cli.js', 'return_rp-mcp': 'mcp.js' }), 'return_rp-mcp');
  assert.equal(entry('tool', { tool: 'cli.js', 'tool-server': 'srv.js', other: 'o.js' }), 'tool-server');
  // Our own control: @isokron/mcp-check ships mcp-check and mcp-check-server and runs as `mcp-check serve`.
  assert.equal(entry('@isokron/mcp-check', { 'mcp-check': 'cli.js', 'mcp-check-server': 'srv.js' }), 'mcp-check');
  assert.equal(entry('plain', { plain: 'a.js', other: 'b.js' }), 'plain', 'no server signal: the package\'s own name, as before');
  assert.equal(entry('plain', { plain: 'a.js', 'plain-mcp': 'b.js' }, 'plain'), 'plain', 'a bin the list names always wins');
});

test('R-SBX-49 a PyPI target may name the extras to install with it (pkg[mcp]), checked like every other field', () => {
  const t = (launch) => ({ id: 's001', repo: 'a/b', ref: 'main', launch: { kind: 'pypi', package: 'arcaeon', version: '0.3.1', ...launch } });
  assert.doesNotThrow(() => validateTarget(t({ extras: ['mcp'] })));
  assert.doesNotThrow(() => validateTarget(t({ extras: ['mcp', 'cli'] })));
  for (const extras of [[], ['MCP'], ['mcp]; rm'], ['a', 'b', 'c', 'd', 'e'], ['mcp', 'mcp'], 'mcp', ['x'.repeat(50)]]) assert.throws(() => validateTarget(t({ extras })), /extras/, JSON.stringify(extras));
  const p = launchPlan(t({ extras: ['mcp', 'cli'] }).launch);
  assert.ok(p.install[1].cmd.includes('arcaeon[mcp,cli]==0.3.1'));
  assert.ok(launchPlan(t({ version: 'latest', extras: ['mcp'] }).launch).install[1].cmd.includes('arcaeon[mcp]'));
  assert.ok(launchPlan(t({}).launch).install[1].cmd.includes('arcaeon==0.3.1'), 'no extras: as before');
});
