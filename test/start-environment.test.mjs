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
import { HarnessError, LIMITS, SANDBOX_USER, imageConfigOf, imagePath, imageWorkdir, run, sandboxRunArgs, tarHead, volumePlan, volumeTmpfs } from '../src/docker.mjs';
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
  assert.deepEqual(cfg, { ok: true, workdir: '/app', workdir_refused: null, code_dirs: [], volumes: ['/data', '/app/logs'], platform: 'linux/amd64' });
  assert.deepEqual(imageConfigOf('{"WorkingDir":"","Volumes":null} linux/amd64'), { ok: true, workdir: null, workdir_refused: null, code_dirs: [], volumes: [], platform: 'linux/amd64' });
  assert.deepEqual(imageConfigOf(''), { ok: false, workdir: null, workdir_refused: null, code_dirs: [], volumes: [], platform: null });
  assert.equal(imageConfigOf('{"WorkingDir":"/app"} /').ok, true, 'an empty Os/Arch is no failed inspect');
  assert.deepEqual(imageConfigOf('{"Entrypoint":["/usr/local/bin/start.sh"],"Cmd":["/srv/app/main.py","--x"]} linux/amd64').code_dirs, ['/usr/local/bin', '/srv/app']);
  for (const bad of ['app', '/', '/app/../etc', '/a b', '/x;rm', '/./x', '//', '/a,size=9g', '/a:rw', '/a=b', '-x', '/a\n', '/a/b\n']) assert.equal(imagePath(bad), null, JSON.stringify(bad));
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
  assert.deepEqual(t, [`/tmp:rw,nosuid,nodev,exec,size=${LIMITS.tmp},mode=1777`, '/data:rw,nosuid,nodev,noexec,size=32m,mode=1777', '/config:rw,nosuid,nodev,noexec,size=32m,mode=1777']);
  hardened(a);
  assert.deepEqual(volumeTmpfs(['/data/', '/data', '/tmp', '/tmp/x', '/proc', '/etc/app', '/dev/shm', 'rel', '/a/../b', 7, '/work', '/work/x', '/opt/surface', '/var/log/supervisor']), ['/data', '/var/log/supervisor']);
  const many = Array.from({ length: 20 }, (_, i) => '/v' + i);
  assert.equal(volumeTmpfs(many).length, LIMITS.volTmpCount);
  assert.equal(LIMITS.volTmpCount, 8);
  assert.equal(LIMITS.volTmp, '32m');
  // tmpfs is memory: /tmp and every volume together stay at most half the memory limit.
  const mib = (x) => Number(String(x).replace(/m$/, '')) * (String(x).endsWith('g') ? 1024 : 1) || Number(String(x).replace(/g$/, '')) * 1024;
  assert.ok(mib(LIMITS.tmp) + LIMITS.volTmpCount * mib(LIMITS.volTmp) <= mib(LIMITS.memory) / 2);
  // sandboxRunArgs never takes a path volumeTmpfs would drop.
  for (const bad of [['/etc'], ['/tmp'], ['rel'], many]) assert.throws(() => sb({ tmpfs: bad }), HarnessError, JSON.stringify(bad).slice(0, 40));
  assert.deepEqual(all(sb(), '--tmpfs').length, 1, 'no image volumes, only /tmp');
});

test('R-SBX-46 a target image is pulled for linux/amd64 only, and its platform is recorded', () => {
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /tdk\.d\(\['pull', '-q', '--platform', 'linux\/amd64', image\]/);
  assert.match(src, /\.\.\.\(ic\.ok \? \{\} : \{ inspect_failed: true \}\)/, 'a failed inspect is recorded, not silent');
  assert.equal(imageConfigOf('{} linux/arm64').platform, 'linux/arm64');
  assert.equal(imageConfigOf('{} linux/arm64;x').platform, null);
});

test('R-SBX-47 an HTTP server\'s own stderr is read back: docker logs writes it to its stderr, which is now kept', async () => {
  // The tail of each stream, cut by bytes, with the cut flagged.
  const big = await run(process.execPath, ['-e', 'process.stderr.write("x".repeat(5000) + "\\nError: the real reason\\n")'], { keepStdout: true, keepStderr: true, tail: true, cap: 1024, logStdout: false });
  assert.equal(big.stderr.length, 1024);
  assert.match(big.stderr.toString(), /Error: the real reason\n$/);
  assert.equal(big.stderr_truncated, true);
  const r = await run(process.execPath, ['-e', 'process.stdout.write("out\\n"); process.stderr.write("Error: missing API_KEY\\n")'], { keepStdout: true, keepStderr: true, logStdout: false });
  assert.equal(r.stdout.toString(), 'out\n');
  assert.equal(r.stderr.toString(), 'Error: missing API_KEY\n');
  assert.equal(r.stderr_bytes, 23);
  const r0 = await run(process.execPath, ['-e', 'process.stderr.write("x")'], {});
  assert.equal(r0.stderr, undefined, 'only when asked');
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /tdk\.d\(\['logs', name\], \{ keepStdout: true, keepStderr: true, tail: true, logStdout: false, cap: 2 \* 1024 \* 1024 \}\)/);
  assert.match(src, /p\.stderr = Buffer\.concat\(\[logs\.stdout, logs\.stderr \|\| Buffer\.alloc\(0\)\]\)/);
  assert.match(src, /p\.stderr_truncated = true/);
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
  // Tools around a server are never it; an exact <name>-mcp wins over another match.
  assert.equal(entry('kit', { kit: 'k.js', 'create-mcp-server': 'c.js', 'mcp-inspector': 'i.js', 'kit-mcp': 'm.js' }), 'kit-mcp');
  assert.equal(entry('kit', { kit: 'k.js', 'mcp-installer': 'i.js', 'zz-mcp': 'z.js', 'kit-mcp': 'm.js' }), 'kit-mcp');
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

test('R-SBX-50 a WORKDIR under /proc, /sys or /dev is refused, recorded, and the server runs in /tmp instead', () => {
  for (const raw of ['/proc/self/fd/7', '/proc', '/sys/fs/cgroup', '/dev/shm', '/dev']) {
    const c = imageConfigOf(JSON.stringify({ WorkingDir: raw }) + ' linux/amd64');
    assert.equal(c.workdir, null, raw);
    assert.equal(c.workdir_refused, raw, raw);
    assert.throws(() => sb({ workdir: raw }), HarnessError, raw);
  }
  assert.equal(imageWorkdir('/app\u0000x').refused, '/app?x', 'cut and printable');
  assert.equal(imageWorkdir('/'.repeat(1) + 'a'.repeat(300)).refused.length, 120);
  assert.deepEqual(imageWorkdir(''), { workdir: null, refused: null });
  assert.deepEqual(imageWorkdir('/procfs/app'), { workdir: '/procfs/app', refused: null }, 'a name that only starts like it is fine');
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /\.\.\.\(ic\.workdir_refused \? \{ workdir_refused: ic\.workdir_refused \} : \{\}\)/);
});

test('R-SBX-51 no tmpfs over a VOLUME that holds the image\'s code or ships content: only empty folders get one, the rest are recorded', () => {
  // Equal to, or holding, its WORKDIR or its entrypoint's folder.
  const vp = volumePlan(['/app', '/', '/srv', '/data', '/usr/local', '/x/../y', '/tmp/a'], ['/app', '/usr/local/bin']);
  assert.deepEqual(vp.volumes, ['/srv', '/data']);
  assert.deepEqual(vp.dropped.map((d) => d.why), ['holds_code', 'not_plain', 'holds_code', 'not_plain', 'reserved']);
  // The head of `docker cp <c>:<path> -`: an empty folder, a folder with a file, a file, a link, garbage.
  const hdr = (name, type, size = 0) => { const b = Buffer.alloc(512); b.write(name, 0, 'latin1'); b.write(size.toString(8).padStart(11, '0') + '\0', 124, 'latin1'); b[156] = type.charCodeAt(0); return b; };
  const end = Buffer.alloc(1024);
  assert.equal(tarHead(Buffer.concat([hdr('data/', '5'), end])), 'empty');
  assert.equal(tarHead(Buffer.concat([hdr('config/', '5'), hdr('config/app.toml', '0', 12), Buffer.alloc(512), end])), 'seeded');
  assert.equal(tarHead(Buffer.concat([hdr('data', '0', 3), Buffer.alloc(512), end])), 'seeded', 'not a folder');
  assert.equal(tarHead(Buffer.concat([hdr('data', '2'), end])), 'seeded', 'a link (one to /etc would hide our resolv.conf)');
  assert.equal(tarHead(Buffer.from('nope')), 'unknown');
  assert.equal(tarHead(Buffer.concat([hdr('data/', '5')])), 'empty', 'nothing after the folder');
  // The run keeps only empty ones and records why the others went.
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /const vp = volumePlan\(ic\.volumes, \[ic\.workdir, \.\.\.ic\.code_dirs\]\)/);
  assert.match(src, /const volumes = vp\.volumes\.filter\(\(v\) => seen\[v\] === 'empty'\)/);
  assert.match(src, /volumes_dropped: dropped\.slice\(0, 20\)/);
  assert.match(src, /volume_seeded: true/);
  // The content probe never starts the image: create with no network and an entrypoint that does not exist, then rm.
  const dsrc = readFileSync(join(root, 'src', 'docker.mjs'), 'utf8');
  assert.match(dsrc, /\['create', '--name', name, \.\.\.labelArgs\(labels\), '--network', 'none', '--entrypoint', '\/surface-never-runs', ref\]/);
  assert.match(dsrc, /finally \{ await this\.d\(\['rm', '-f', name\]/);
  assert.ok(!/\['start'/.test(dsrc), 'nothing of ours starts a created container');
});

test('R-SBX-52 an image whose inspect names another platform than linux/amd64 is not run: platform_unsupported, our limit', () => {
  const src = readFileSync(join(root, 'bin', 'run-shard.mjs'), 'utf8');
  assert.match(src, /if \(ic\.platform && ic\.platform !== 'linux\/amd64'\) \{\n\s+inst\.oci\.platform_unsupported = true;\n\s+inst\.steps\.push\(\{ name: 'platform', exit: 1, timed_out: false, ms: 0 \}\);\n\s+\} else inst\.ok = true;/);
  assert.equal(imageConfigOf('{} linux/arm64').platform, 'linux/arm64');
});
