// The writable layer a package kind's server may get (src/docker.mjs writableLayer, bin/run-shard.mjs writableWork):
// an overlay over its work volume at /work and a /data tmpfs. What is checked here: the overlay's folders are the
// data-root's own volume folders and nothing else, the layer is made, checked and removed as described, a server with
// it keeps every other setting, the guard's settings check still refuses what it refused, and the work-overlay case of
// the hostile self test (and its two mutations) decides as it should.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DATA_TMPFS, Docker, HarnessError, LAYER_CHECK_CMD, LAYER_CMD, LIMITS, WRITABLE_KINDS, overlayOptions, overlayVolumeArgs, sandboxRunArgs, volumeDataPath, volumeMount } from '../src/docker.mjs';
import { inspectMismatches, settingsManifest } from '../src/sandbox-env.mjs';
import { LAYER_FILL_MB, LAYER_SEED, LAYER_WRITES, READOUT_PATHS, VOLUME_CAP, evaluateCase } from '../src/selftest.mjs';
import { EXPECT, checkMutation } from '../scripts/check-mutation.mjs';
import { MUTATIONS, layerSeedCmd, seedContent } from '../bin/sandbox-selftest.mjs';
import { mutationTelemetry } from './evidence-fixtures.mjs';
import { GOOD } from './selftest-fixtures.mjs';
import { tree } from '../selftest/stage.mjs';
import { loadRunscConfig } from '../src/runsc.mjs';

const ROOT = '/var/lib/isokron-docker';
const IMG = `docker.io/library/node:24-bookworm-slim@sha256:${'d'.repeat(64)}`;
const val = (a, flag) => (a.indexOf(flag) < 0 ? null : a[a.indexOf(flag) + 1]);

test('R-SBX-57 a layer\'s overlay names only the data-root\'s own folders of a work volume and a fresh upper volume, nosuid and nodev; any other path is refused', () => {
  assert.equal(loadRunscConfig().docker_root, ROOT, 'the data-root install-runsc.sh makes');
  assert.equal(volumeDataPath(ROOT, 'surface-r1-s001-work'), `${ROOT}/volumes/surface-r1-s001-work/_data`);
  const o = overlayOptions({ root: ROOT, lower: 'surface-r1-s001-work', upper: 'surface-r1-s001-up3' });
  assert.equal(o, `lowerdir=${ROOT}/volumes/surface-r1-s001-work/_data,upperdir=${ROOT}/volumes/surface-r1-s001-up3/_data/upper,workdir=${ROOT}/volumes/surface-r1-s001-up3/_data/work,nosuid,nodev`);
  // One lower layer (a colon would add another), no exec or suid flag, no other option.
  const parts = o.split(',');
  assert.deepEqual(parts.map((p) => p.split('=')[0]), ['lowerdir', 'upperdir', 'workdir', 'nosuid', 'nodev']);
  assert.ok(!o.includes(':'));
  for (const bad of ['surface-a,upperdir=/', 'surface-a:/etc', '../surface-a', 'surface-A', 'other-volume', '', 'surface-a/../../x']) {
    assert.throws(() => overlayOptions({ root: ROOT, lower: bad, upper: 'surface-r1-up1' }), HarnessError, `lower ${bad}`);
    assert.throws(() => overlayOptions({ root: ROOT, lower: 'surface-r1-work', upper: bad }), HarnessError, `upper ${bad}`);
  }
  for (const root of ['var/lib/docker', '/var/lib/../../etc', '/var/lib/x,lowerdir=/', '/var/lib/x:y', '/', '']) assert.throws(() => volumeDataPath(root, 'surface-a'), HarnessError, `root ${root}`);
  assert.throws(() => overlayOptions({ root: ROOT, lower: 'surface-a', upper: 'surface-a' }), /never its lower/);
  const argv = overlayVolumeArgs({ name: 'surface-r1-s001-layer4', root: ROOT, lower: 'surface-r1-s001-work', upper: 'surface-r1-s001-up3', labels: { 'isokron.surface.run': 'r1' } });
  assert.deepEqual(argv, ['volume', 'create', '--driver', 'local', '--opt', 'type=overlay', '--opt', 'device=overlay', '--opt', `o=${o}`, '--label', 'isokron.surface.run=r1', 'surface-r1-s001-layer4']);
  for (const name of ['surface-r1-s001-work', 'surface-r1-s001-up3', 'x', 'surface-a,b']) assert.throws(() => overlayVolumeArgs({ name, root: ROOT, lower: 'surface-r1-s001-work', upper: 'surface-r1-s001-up3' }), HarnessError, name);
  // The layer is mounted like any volume of ours, and never seeded from the image.
  assert.equal(volumeMount({ src: 'surface-r1-s001-layer4', dst: '/work', nocopy: true }), 'type=volume,src=surface-r1-s001-layer4,dst=/work,volume-nocopy');
  assert.deepEqual([...WRITABLE_KINDS].sort(), ['cargo', 'go', 'mcpb', 'npm', 'nuget', 'pypi']);
  assert.deepEqual([...DATA_TMPFS], ['/data']);
});

/** A Docker session that answers volume and helper calls from a script. */
class LayerDocker extends Docker {
  constructor(opts = {}) {
    super({ runId: 'r1' });
    this.calls = []; this.vols = new Map(); this.opts = opts;
  }
  d(argv) {
    this.calls.push(argv);
    const out = (s, exit = 0) => Promise.resolve({ exit, signal: null, timed_out: false, stdout: Buffer.from(s), stdout_bytes: s.length, stdout_truncated: false, stderr_tail: Buffer.alloc(0), ms: 1 });
    const [a, b] = argv; const name = argv[argv.length - 1];
    if (a === 'volume' && b === 'inspect') {
      if (!this.vols.has(name)) return out('', 1);
      const f = argv[3];
      if (f === '{{.Mountpoint}}') return out(`${this.opts.mountpoint ? this.opts.mountpoint(name) : `${ROOT}/volumes/${name}/_data`}\n`);
      if (f.startsWith('{{.Driver}}')) return out(`local ${JSON.stringify(this.opts.options ? this.opts.options(this.vols.get(name)) : this.vols.get(name))}\n`);
      return out(`${name}\n`);
    }
    if (a === 'volume' && b === 'create') {
      const o = {};
      for (let i = 0; i < argv.length; i++) if (argv[i] === '--opt') { const [k, ...v] = argv[i + 1].split('='); o[k] = v.join('='); }
      if (this.opts.createFails && o.type === 'overlay') return out('', 1);
      this.vols.set(name, o); return out(`${name}\n`);
    }
    if (a === 'volume' && b === 'rm') { if (!this.opts.keep) for (const v of argv.slice(3)) this.vols.delete(v); return out(''); }
    if (a === 'run') return out('', this.opts.checkFails && argv.join(' ').includes(LAYER_CHECK_CMD) ? 1 : 0);
    return out('');
  }
}

test('R-SBX-58 a layer: a fresh upper volume made 65534\'s by a root helper with CAP_CHOWN only, the overlay volume with exactly our options read back, a check through it; removed whole, and said so', async () => {
  const dk = new LayerDocker();
  dk.vols.set('surface-r1-s001-work', {});
  const layer = await dk.writableLayer('surface-r1-s001-work', { root: ROOT, image: IMG, target: 's001' });
  assert.match(layer.volume, /^surface-r1-s001-layer\d+$/);
  assert.match(layer.upper, /^surface-r1-s001-up\d+$/);
  assert.equal(layer.lower, 'surface-r1-s001-work');
  const runs = dk.calls.filter((a) => a[0] === 'run');
  assert.equal(runs.length, 2);
  const [mk, check] = runs;
  // The upper volume's folders: root in the container with CAP_CHOWN only, under gVisor, no network, the upper volume alone.
  assert.equal(val(mk, '--runtime'), 'runsc');
  assert.equal(val(mk, '--user'), '0:0');
  assert.deepEqual(mk.filter((x, i) => mk[i - 1] === '--cap-add'), ['CHOWN']);
  assert.equal(val(mk, '--network'), 'none');
  assert.deepEqual(mk.filter((x, i) => mk[i - 1] === '--mount'), [`type=volume,src=${layer.upper},dst=/layer`]);
  assert.equal(mk[mk.length - 1], LAYER_CMD);
  assert.match(LAYER_CMD, /chmod 0750 \/layer\/upper && chown 65534:65534 \/layer\/upper$/);
  // The overlay volume, over the work volume's own folder, and the check: 65534, the layer read-only, never seeded.
  const create = dk.calls.find((a) => a[0] === 'volume' && a[1] === 'create' && a.includes('type=overlay'));
  assert.deepEqual(create, overlayVolumeArgs({ name: layer.volume, root: ROOT, lower: 'surface-r1-s001-work', upper: layer.upper, labels: dk.labels('s001') }));
  assert.ok(dk.calls.indexOf(create) > dk.calls.indexOf(mk), 'the overlay after its upper folders exist');
  assert.equal(val(check, '--user'), '65534:65534');
  assert.equal(val(check, '--runtime'), 'runsc');
  assert.deepEqual(check.filter((x, i) => check[i - 1] === '--mount'), [`type=volume,src=${layer.volume},dst=/work,readonly,volume-nocopy`]);
  assert.ok(dk.calls.indexOf(check) > dk.calls.indexOf(create));
  // Removed: the overlay volume, then its upper one; the work volume stays.
  assert.equal(await dk.dropLayer(layer), true);
  const rms = dk.calls.filter((a) => a[0] === 'volume' && a[1] === 'rm').map((a) => a[3]);
  assert.deepEqual(rms, [layer.volume, layer.upper]);
  assert.ok(dk.vols.has('surface-r1-s001-work'));
  // A layer Docker still lists after its removal is said to be there.
  const keep = new LayerDocker({ keep: true });
  keep.vols.set('surface-r1-s001-work', {});
  assert.equal(await keep.dropLayer(await keep.writableLayer('surface-r1-s001-work', { root: ROOT, image: IMG, target: 's001' })), false);
});

test('R-SBX-58 a layer is refused when Docker keeps a volume anywhere but its data-root, when the overlay\'s options are not ours, or when the check through it fails', async () => {
  const mk = (opts) => { const dk = new LayerDocker(opts); dk.vols.set('surface-r1-s001-work', {}); return dk.writableLayer('surface-r1-s001-work', { root: ROOT, image: IMG, target: 's001' }); };
  await assert.rejects(mk({ mountpoint: (n) => `/home/runner/work/${n}` }), /is not kept in \/var\/lib\/isokron-docker\/volumes/);
  await assert.rejects(mk({ mountpoint: (n) => (n.endsWith('-work') ? '/' : `${ROOT}/volumes/${n}/_data`) }), /is not kept in/);
  await assert.rejects(mk({ options: (o) => ({ ...o, o: `${o.o},redirect_dir=on` }) }), /options are not the ones the harness gave/);
  await assert.rejects(mk({ options: (o) => ({ ...o, size: '1g' }) }), /options are not the ones/);
  await assert.rejects(mk({ options: () => ({ type: 'none', device: '/', o: 'bind' }) }), /options are not the ones/);
  await assert.rejects(mk({ createFails: true }), /writable layer: overlay volume failed/);
  await assert.rejects(mk({ checkFails: true }), /writable layer: check failed/);
  const dk = new LayerDocker();
  await assert.rejects(dk.writableLayer('surface-r1-s001-work', { root: ROOT, image: 'node:24', target: 's001' }), /not pinned by digest/);
  await assert.rejects(dk.writableLayer('../etc', { root: ROOT, image: IMG, target: 's001' }), /only surface volumes/);
});

test('R-SBX-60 a server with the layer keeps every other setting; /data is a tmpfs like an image VOLUME\'s; the guard\'s settings check accepts the layer and still refuses a host path, the bare work volume or a writable root', () => {
  const layer = { src: 'surface-r1-s001-layer4', dst: '/work', nocopy: true };
  const argv = sandboxRunArgs({ name: 'surface-r1-s001-s5', image: IMG, network: 'surface-r1-s001-run', detach: true, mounts: [layer], tmpfs: [...DATA_TMPFS], env: { HOME: '/tmp/home' }, cmd: ['node', '/work/pkg/x.js'], hostEnv: {} });
  const plain = sandboxRunArgs({ name: 'surface-r1-s001-s5', image: IMG, network: 'surface-r1-s001-run', detach: true, mounts: [{ src: 'surface-r1-s001-work', dst: '/work', ro: true }], env: { HOME: '/tmp/home' }, cmd: ['node', '/work/pkg/x.js'], hostEnv: {} });
  const flags = (a) => a.filter((x, i) => !['--mount', '--tmpfs'].includes(x) && !['--mount', '--tmpfs'].includes(a[i - 1]));
  assert.deepEqual(flags(argv), flags(plain), 'only the mount and the /data tmpfs differ');
  for (const f of ['--read-only', '--init']) assert.ok(argv.includes(f), f);
  assert.equal(val(argv, '--runtime'), 'runsc');
  assert.equal(val(argv, '--user'), '65534:65534');
  assert.ok(argv.join(' ').includes('--cap-drop ALL --security-opt no-new-privileges --read-only'));
  const tmpfs = argv.filter((x, i) => argv[i - 1] === '--tmpfs');
  assert.deepEqual(tmpfs, [`/tmp:rw,nosuid,nodev,exec,size=${LIMITS.tmp},mode=1777`, `/data:rw,nosuid,nodev,noexec,size=${LIMITS.volTmp},mode=1777`]);
  assert.deepEqual(argv.filter((x, i) => argv[i - 1] === '--mount'), ['type=volume,src=surface-r1-s001-layer4,dst=/work,volume-nocopy']);
  const m = settingsManifest(argv, { role: 'server' });
  assert.deepEqual(m.mounts, [{ type: 'volume', src: 'surface-r1-s001-layer4', dst: '/work', ro: false }]);
  assert.ok(m.tmpfs.includes(`/data:rw,nosuid,nodev,noexec,size=${LIMITS.volTmp},mode=1777`));
  // docker inspect of that container: as declared, it passes; anything else at /work, or a writable root, does not.
  const ins = (mounts, extra = {}) => ({ HostConfig: { Runtime: 'runsc', CapDrop: ['ALL'], CapAdd: null, SecurityOpt: ['no-new-privileges'], ReadonlyRootfs: true, PidsLimit: Number(LIMITS.pids), Ulimits: [{ Name: 'nofile', Soft: 4096, Hard: 4096 }, { Name: 'nproc', Soft: 512, Hard: 512 }], Memory: 2 * 1024 ** 3, NanoCpus: 2e9, NetworkMode: 'surface-r1-s001-run', LogConfig: { Type: m.log_driver, Config: Object.fromEntries(m.log_opts.map((o) => o.split('='))) }, ...extra }, Config: { User: '65534:65534', Env: ['HOME=/tmp/home'] }, Mounts: mounts });
  const ok = [{ Type: 'volume', Name: 'surface-r1-s001-layer4', Destination: '/work', RW: true, Driver: 'local' }];
  assert.deepEqual(inspectMismatches(ins(ok), m), []);
  assert.deepEqual(inspectMismatches(ins([{ Type: 'bind', Source: '/var/lib/isokron-docker/volumes/surface-r1-s001-work/_data', Destination: '/work', RW: true }]), m), ['unexpected mount at /work']);
  assert.deepEqual(inspectMismatches(ins([{ Type: 'volume', Name: 'surface-r1-s001-work', Destination: '/work', RW: true }]), m), ['unexpected mount at /work'], 'the work volume itself, writable, is not the layer');
  assert.deepEqual(inspectMismatches(ins([{ Type: 'volume', Name: 'surface-r1-s001-layer4', Destination: '/', RW: true }]), m), ['unexpected mount at /']);
  assert.deepEqual(inspectMismatches(ins(ok, { ReadonlyRootfs: false }), m), ['the root filesystem is not read-only']);
  assert.ok(inspectMismatches(ins(ok, { Binds: ['/:/host'] }), m).includes('has -v binds'));
  // A layer is no way past the tmpfs rules: /data only where we put it, never over our own folders.
  for (const t of [['/work'], ['/opt/surface'], ['/etc'], ['/tmp/x']]) assert.throws(() => sandboxRunArgs({ name: 'surface-x', image: IMG, network: 'surface-x-run', mounts: [layer], tmpfs: t, cmd: ['x'], hostEnv: {} }), /tmpfs path/);
});

test('R-CASE-29 work-overlay: blocked only when the work volume under the layer is as seeded, a fresh layer shows nothing the case wrote, the layer is gone, and nothing left /work, /tmp and /data; it needs its positive controls', () => {
  const g = (f) => { const ev = GOOD['work-overlay'](); f(ev); return evaluateCase('work-overlay', ev); };
  const good = g(() => {});
  assert.deepEqual([good.blocked, good.logged, good.pass], [true, true, true], good.detail);
  const cases = [
    ['the work volume under the layer changed', (ev) => { ev.stage.lower = { intact: false, entries: 12, changed: 2 }; }, /^got through: the case's writes reached the work volume under the overlay \(2 entries changed\)/],
    ['a fresh layer shows a write', (ev) => { ev.stage.fresh.leaked = ['/work/isk-new-1']; }, /^got through: a fresh layer over the same work volume shows what the case wrote/],
    ['the layer outlived its teardown', (ev) => { ev.stage.layer_gone = false; }, /^got through: the case's layer outlived its teardown/],
    ['the readout met a link', (ev) => { ev.stage.readout[0] = { path: READOUT_PATHS[0], exit: 3, bytes: 0, seeded: false }; }, /^got through: the result readout did not read the seeded files/],
    ['the readout read other bytes', (ev) => { ev.stage.readout[2].seeded = false; }, /^got through: the result readout/],
    ['the host canary changed', (ev) => { ev.stage.host = { intact: false, planted: 0 }; }, /^got through: the host's canary file changed/],
    ['a file appeared beside the host canary', (ev) => { ev.stage.host = { intact: true, planted: 1 }; }, /^got through: 1 file\(s\) appeared in the host's canary folder/],
    ['the runner\'s disk fell', (ev) => { ev.stage.disk.host_free_drop_mb = 900; }, /^got through: the runner's disk lost 900 MB/],
    ['the layer past the volume cap', (ev) => { ev.stage.disk.layer_fs_mb = 70000; }, /^got through: the layer's filesystem holds 70000 MB/],
    ['a write outside', (ev) => { ev.trace.opens_outside[0] = { path: '/etc/isk-1', op: 'write', call: 'openat', n: 1, failed: 0, errno: null }; }, /^got through: a write outside \/work, \/tmp and \/data worked \(\/etc\/isk-1\)/],
    ['umount worked', (ev) => { ev.trace.privileged[1] = { name: 'umount2', n: 1, failed: 0, errno: null }; }, /^got through: umount2 worked/],
    ['a file handle opened', (ev) => { ev.trace.privileged[2] = { name: 'open_by_handle_at', n: 1, failed: 0, errno: null }; }, /^got through: open_by_handle_at worked/],
    ['a hard link was made', (ev) => { ev.trace.links.push({ kind: 'hard', target: '/etc/passwd', path: '/work/h', n: 1, failed: 0, errno: null }); }, /^got through: a hard link was made/],
    ['nothing landed in the layer', (ev) => { Object.assign(ev.stage.disk, { landed: 1, layer_bytes_mb: 0 }); }, /^not shown to work: the case's writes did not land in the layer/],
    ['the fill did not land', (ev) => { ev.stage.disk.layer_bytes_mb = 3; }, /^not shown to work: the case's writes did not land/],
    ['a fresh layer without the seeded files', (ev) => { ev.stage.fresh.seeded = false; }, /^not shown to work: a fresh layer does not show the seeded work volume/],
    ['no stage', (ev) => { delete ev.stage; }, /^not measured: the later stage did not run/],
    ['no host disk reading', (ev) => { delete ev.stage.disk.host_free_drop_mb; }, /^not measured: the runner's free disk/],
    ['no umount tried', (ev) => { ev.trace.privileged = ev.trace.privileged.filter((p) => p.name !== 'umount2'); }, /^nothing was tried: .*umount2 not traced/],
    ['too few writes outside', (ev) => { ev.trace.opens_outside = ev.trace.opens_outside.slice(3); }, /^nothing was tried: 2 write\(s\) outside traced/],
  ];
  for (const [what, f, why] of cases) {
    const v = g(f);
    assert.equal(v.pass, false, what);
    assert.equal(v.blocked, false, what);
    assert.match(v.detail, why, what);
  }
  // The target's report can only fail it: an allocation past the cap, /data past its cap, a trusted.overlay attribute,
  // a whiteout device, the host's canary read through a link, a write through a link to outside.
  const capped = { ok: false, errno: 28, error: 'ENOSPC', bytes: 32 << 20 };
  const rep = (result) => (ev) => { ev.report = { case: 'work-overlay', result: { data_fill: capped, fallocate: { ok: false, errno: 28 }, xattrs: [{ name: 'user.overlay.redirect', ok: true }], whiteout: { ok: false, errno: 1 }, ...result } }; };
  assert.equal(g(rep({})).pass, true, 'a report of refusals (a user xattr is no overlay attribute here) does not fail it');
  for (const [what, r, why] of [
    ['an allocation past the cap', { fallocate: { ok: true, bytes: 7 << 30 } }, /allocation past the volume filesystem's cap/],
    ['/data past its cap', { data_fill: { ok: true, bytes: 40 << 20 } }, /\/data took 41943040 bytes, past its 32m cap/],
    ['/data stopped but not with ENOSPC', { data_fill: { ok: false, errno: 5, bytes: 1 << 20 } }, /\/data took/],
    ['no /data fill reported', { data_fill: undefined }, /\/data took 0 bytes/],
    ['a trusted.overlay attribute', { xattrs: [{ name: 'trusted.overlay.redirect', ok: true }] }, /trusted\.overlay attribute/],
    ['a whiteout device', { whiteout: { ok: true } }, /whiteout device/],
    ['the canary read', { canary_seen: 1 }, /host's canary through a link/],
    ['a write through a link', { attempts: [{ path: '/work/isk-l01/isk-1', via: '/etc', ok: true, written: true }] }, /write through a link to outside/],
  ]) {
    const v = g(rep(r));
    assert.equal(v.pass, false, what);
    assert.match(v.detail, why, what);
  }
  // Logged needs the stage's three readings, the writes outside, the links out and the /data write.
  for (const f of [(ev) => { ev.trace.links = ev.trace.links.slice(2); }, (ev) => { ev.trace.opens_outside = ev.trace.opens_outside.filter((o) => !o.path.startsWith('/data/')); }, (ev) => { delete ev.stage.fresh; }]) assert.equal(g(f).logged, false);
  // The fill lands in the layer before the allocation past the cap: the cap is the volume filesystem's.
  assert.ok(LAYER_FILL_MB >= 64 && LAYER_FILL_MB * 4 < VOLUME_CAP.mb);
  assert.ok(LAYER_SEED.length >= 5 && READOUT_PATHS.every((p) => LAYER_SEED.includes(p)), 'the read-out files are seeded');
  assert.ok(LAYER_WRITES('1').every((p) => p.startsWith('/work/')));
});

test('R-CASE-29 work-overlay: the seed is ours (paths and nonce), each file one line the readout can compare, and the tree reads a folder without following its links', () => {
  const cmd = layerSeedCmd('0123456789abcdef');
  for (const p of LAYER_SEED) assert.ok(cmd.includes(`printf '%s\\n' 'isk-seed-0123456789abcdef ${p}' > ${p}`), p);
  assert.equal(seedContent('/work/lock/freeze.txt', '0123456789abcdef'), 'isk-seed-0123456789abcdef /work/lock/freeze.txt\n');
  for (const bad of ['x; rm -rf /', '', '0123456789ABCDEF', '$(id)']) assert.throws(() => layerSeedCmd(bad), /nonce of ours/);
  const d = mkdtempSync(join(tmpdir(), 'tree-'));
  const t0 = tree(d);
  assert.deepEqual([t0.entries, t0.items], [0, []]);
  mkdirSync(join(d, 'lock')); writeFileSync(join(d, 'lock', 'freeze.txt'), 'a\n'); symlinkSync('/etc', join(d, 'l'));
  const t1 = tree(d);
  assert.equal(t1.entries, 3, 'the link is one entry: /etc is not walked');
  assert.deepEqual(t1.items.map(([p]) => p), ['l', 'lock', 'lock/freeze.txt']);
  writeFileSync(join(d, 'lock', 'freeze.txt'), 'b\n');
  assert.notEqual(tree(d).sha256, t1.sha256, 'a file\'s bytes count');
  writeFileSync(join(d, 'lock', 'freeze.txt'), 'a\n');
  assert.equal(tree(d).sha256, t1.sha256, 'and only its bytes, mode and kind: not its times');
  rmSync(join(d, 'l')); symlinkSync('/root', join(d, 'l'));
  assert.notEqual(tree(d).sha256, t1.sha256, 'a link\'s target counts');
});

test('R-MUT-12 overlay-lower-rw: work-overlay on its work volume itself, read-write, is caught by the work volume under the layer changing', () => {
  assert.match(MUTATIONS['overlay-lower-rw'], /work volume itself, read-write/);
  const f = join(mkdtempSync(join(tmpdir(), 'mut-')), 'telemetry.jsonl');
  mutationTelemetry(f, 'overlay-lower-rw');
  const r = checkMutation(f, 'overlay-lower-rw');
  assert.equal(r.ok, true, r.lines.join('\n'));
  assert.equal(EXPECT['overlay-lower-rw'].case, 'work-overlay');
  // The evidence of a working layer does not show it.
  const g = join(mkdtempSync(join(tmpdir(), 'mut-')), 'telemetry.jsonl');
  mutationTelemetry(g, 'overlay-keep');
  assert.equal(checkMutation(g, 'overlay-lower-rw').ok, false);
});

test('R-MUT-13 overlay-keep: a layer left after its container was torn down is caught by work-overlay asking Docker for it', () => {
  assert.match(MUTATIONS['overlay-keep'], /not removed/);
  const f = join(mkdtempSync(join(tmpdir(), 'mut-')), 'telemetry.jsonl');
  mutationTelemetry(f, 'overlay-keep');
  const r = checkMutation(f, 'overlay-keep');
  assert.equal(r.ok, true, r.lines.join('\n'));
  const g = join(mkdtempSync(join(tmpdir(), 'mut-')), 'telemetry.jsonl');
  mutationTelemetry(g, 'overlay-lower-rw');
  assert.equal(checkMutation(g, 'overlay-keep').ok, false, 'another protection\'s failure does not count for this one');
});
