import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRunscConfig, normArch, runscFlags } from '../src/runsc.mjs';
import { plan, verifyRuntimes } from '../scripts/runsc-plan.mjs';

// scripts/install-runsc.sh with its test-only switches: a local bundle (RUNSC_BUNDLE), another
// gvisor.json (RUNSC_CONFIG), a scratch root (RUNSC_PREFIX) and no daemon (RUNSC_SKIP_DAEMON).
// A curl on PATH that only leaves a mark: these tests never reach the network.
const root = fileURLToPath(new URL('..', import.meta.url));
const cfg = loadRunscConfig();
const arch = normArch(execFileSync('uname', ['-m'], { encoding: 'utf8' }).trim());
const sha512 = (f) => createHash('sha512').update(readFileSync(f)).digest('hex');

/** A stand-in with the bundle's layout; its runsc only prints a version. */
function fakeBundle(dir, extra = {}) {
  const src = join(dir, 'bundle-src');
  mkdirSync(join(src, 'gvisor-bin'), { recursive: true });
  writeFileSync(join(src, 'runsc'), '#!/bin/sh\necho "runsc version fake"\n', { mode: 0o755 });
  writeFileSync(join(src, 'containerd-shim-runsc-v1'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  writeFileSync(join(src, 'gvisor-bin', 'gvisor_sentry'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  for (const [p, body] of Object.entries(extra)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), body); }
  const f = join(dir, 'gvisor.tar.bz2');
  execFileSync('tar', ['-cjf', f, '-C', src, ...readdirSync(src).sort()], { env: { ...process.env, COPYFILE_DISABLE: '1' } });
  return f;
}

/** gvisor.json with the fake bundle's checksum in place of the pinned one. */
function configFor(dir, bundle) {
  const c = JSON.parse(readFileSync(join(root, 'gvisor.json'), 'utf8'));
  for (const a of Object.keys(c.bundles)) c.bundles[a].sha512 = sha512(bundle);
  const f = join(dir, 'gvisor.json');
  writeFileSync(f, JSON.stringify(c));
  return f;
}

function install(t, env = {}) {
  const bin = join(t, 'bin');
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'curl'), `#!/bin/sh\necho "$@" >> '${join(t, 'curl-called')}'\nexit 7\n`, { mode: 0o755 });
  const r = spawnSync('bash', [join(root, 'scripts/install-runsc.sh'), process.execPath], {
    cwd: root, encoding: 'utf8',
    env: { PATH: `${bin}:${process.env.PATH}`, HOME: t, RUNSC_PREFIX: join(t, 'root'), RUNSC_SKIP_DAEMON: '1', ...env },
  });
  return { ...r, out: `${r.stdout}${r.stderr}` };
}

/** Every file and link under the scratch root (directories left out). */
function tree(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true }).filter((p) => !lstatSync(join(dir, p)).isDirectory()).sort();
}

test('install-runsc: a bundle that does not match the pinned sha512 installs nothing', () => {
  const t = mkdtempSync(join(tmpdir(), 'runsc-'));
  const r = install(t, { RUNSC_BUNDLE: fakeBundle(t) });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /harness error: .*checksum mismatch/);
  assert.match(r.out, /nothing installed/);
  assert.deepEqual(tree(join(t, 'root')), [], 'no runsc, no symlink, no log folder');
  assert.equal(existsSync(join(t, 'root', cfg.log_dir)), false);
  assert.equal(existsSync(join(t, 'curl-called')), false, 'a local bundle is never downloaded');
});

test('install-runsc: a download that fails installs nothing; the url is the pinned one', () => {
  const t = mkdtempSync(join(tmpdir(), 'runsc-'));
  const r = install(t);
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /harness error: .*download/);
  assert.ok(readFileSync(join(t, 'curl-called'), 'utf8').includes(cfg.bundles[arch].url));
  assert.deepEqual(tree(join(t, 'root')), []);
});

test('install-runsc: the checked bundle unpacks under its release, runsc on PATH, a trace folder the harness can read', () => {
  const t = mkdtempSync(join(tmpdir(), 'runsc-'));
  const bundle = fakeBundle(t);
  const env = { RUNSC_BUNDLE: bundle, RUNSC_CONFIG: configFor(t, bundle) };
  const r = install(t, env);
  assert.equal(r.status, 0, r.out);
  const p = join(t, 'root');
  const dest = join(p, cfg.install_dir, cfg.release);
  assert.ok(statSync(join(dest, 'runsc')).mode & 0o100, 'runsc is executable');
  assert.ok(existsSync(join(dest, 'gvisor-bin', 'gvisor_sentry')), 'the helpers stay next to runsc');
  assert.equal(readlinkSync(join(p, cfg.install_dir, 'current')), cfg.release);
  assert.equal(readlinkSync(join(p, 'usr/local/bin/runsc')), join(cfg.install_dir, cfg.release, 'runsc'));
  assert.equal(readlinkSync(join(p, 'usr/local/bin/containerd-shim-runsc-v1')), join(cfg.install_dir, cfg.release, 'containerd-shim-runsc-v1'));
  assert.equal(statSync(join(p, cfg.log_dir)).mode & 0o777, 0o750);
  assert.equal(statSync(dest).mode & 0o022, 0, 'nobody but root writes the install');
  assert.match(r.stdout, new RegExp(`gVisor ${cfg.release.replace('.', '\\.')} installed`));
  assert.match(r.stdout, /runtime not registered \(RUNSC_SKIP_DAEMON\)/);
  const before = tree(p);
  const again = install(t, env);
  assert.equal(again.status, 0, again.out);
  assert.deepEqual(tree(p), before, 'a second run leaves the same files');
  assert.equal(existsSync(join(t, 'curl-called')), false);
});

test('install-runsc: a bundle with anything else in it is refused, even when the checksum matches', () => {
  for (const extra of [{ 'extra/evil.sh': 'echo hi\n' }, { 'gvisor-bin/sub/deeper': 'x' }]) {
    const t = mkdtempSync(join(tmpdir(), 'runsc-'));
    const bundle = fakeBundle(t, extra);
    const r = install(t, { RUNSC_BUNDLE: bundle, RUNSC_CONFIG: configFor(t, bundle) });
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /harness error: .*unexpected/);
    assert.deepEqual(tree(join(t, 'root')), [], JSON.stringify(extra));
  }
});

test('runsc-plan: the plan is gvisor.json and runscFlags, line for line; the install checks the daemon with it', () => {
  for (const a of ['x86_64', 'aarch64']) {
    const lines = plan(cfg, a);
    assert.deepEqual(lines.slice(0, 9), [`release=${cfg.release}`, 'runtime=runsc', `url=${cfg.bundles[a].url}`, `sha512=${cfg.bundles[a].sha512}`, `install_dir=${cfg.install_dir}`, `log_dir=${cfg.log_dir}`, `trace_fs_mb=${cfg.trace_fs_mb}`, `volume_fs_mb=${cfg.volume_fs_mb}`, `volume_fs_inodes=${cfg.volume_fs_inodes}`]);
    assert.deepEqual(lines.slice(9), runscFlags(cfg, a).map((f) => `flag=${f}`));
  }
  const run = (args, input = '') => spawnSync(process.execPath, [join(root, 'scripts/runsc-plan.mjs'), ...args], { input, encoding: 'utf8' });
  assert.equal(run(['--arch', 'x86_64']).stdout, `${plan(cfg, 'x86_64').join('\n')}\n`);
  const bad = run(['--arch', 'riscv64']);
  assert.deepEqual([bad.status, bad.stdout.trim()], [1, 'harness error: no gVisor bundle for riscv64']);
  const good = JSON.stringify({ runc: { path: 'runc' }, runsc: { path: '/x/runsc', runtimeArgs: runscFlags(cfg, 'x86_64') } });
  assert.equal(verifyRuntimes(cfg, 'x86_64', good), null);
  assert.match(verifyRuntimes(cfg, 'x86_64', JSON.stringify({ runc: {} })), /no runtime runsc/);
  assert.match(verifyRuntimes(cfg, 'x86_64', JSON.stringify({ runsc: { runtimeArgs: ['--network=host'] } })), /flags/);
  assert.match(verifyRuntimes(cfg, 'aarch64', good), /flags/, 'the arm64 trace list differs');
  assert.equal(run(['--verify-runtimes', '--arch', 'x86_64'], good).status, 0);
  assert.equal(run(['--verify-runtimes', '--arch', 'x86_64'], 'not json').status, 1);
});

test('R-SBX-23 install-runsc.sh puts Docker\'s volumes on a filesystem of their own, of volume_fs_mb and volume_fs_inodes, while the daemon is stopped and before any volume exists', () => {
  const sh = readFileSync(join(root, 'scripts/install-runsc.sh'), 'utf8');
  const at = (x) => { const i = sh.indexOf(x, sh.indexOf('volumes_dir="$docker_root/volumes"')); assert.ok(i > 0, x); return i; };
  assert.match(sh, /docker info --format '\{\{\.DockerRootDir\}\}'/);
  assert.ok(at('docker volume ls -q') < at('systemctl stop docker ||'), 'no volume may exist yet');
  assert.ok(at('systemctl stop docker ||') < at('mount -o loop,nosuid,nodev "$vimg" "$volumes_dir"'), 'mounted while the daemon is stopped');
  assert.ok(at('mkfs.ext4 -q -F -m 0 -E nodiscard -N "$volume_fs_inodes" "$vimg"') < at('mount -o loop'), 'nodiscard: a discard would punch holes through the reservation (seen on GitHub: the runner lost 2 GB as the bomb filled the volume)');
  assert.ok(!/mount -o loop,[^"]*discard/.test(sh), 'and no online discard either');
  assert.ok(at('fallocate -l "${volume_fs_mb}M" "$vimg"') > 0, 'the whole size is reserved up front: the cap never draws on the runner\'s disk later');
  assert.ok(at('mountpoint -q "$volumes_dir" || fail') < sh.indexOf('systemctl restart docker'), 'checked before the daemon comes back');
  assert.ok(!/mount -o loop,nosuid,nodev,noexec "\$vimg"/.test(sh), 'targets run programs from their work volume: no noexec');
  assert.ok(sh.indexOf('# 5b. Docker') > 0, 'the step is documented in the header');
});
