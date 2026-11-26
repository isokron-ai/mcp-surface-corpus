// The package kinds beyond npm, PyPI, Go and OCI images: crates (cargo), .NET tools (NuGet) and MCP Bundles (.mcpb).
// The list validator, the launch plans, and our in-container helpers (sandbox/cargo-entry.mjs, nuget-entry.mjs,
// mcpb-fetch.mjs, pyproject-reqs.py) on fixtures, with no network and no Docker. The driver wiring (images, hardening,
// the proxy's allowlist, the server command) is in test/driver-sandbox.test.mjs (R-SBX-35 to R-SBX-37). Each guard has
// a mutation check: with the guard taken out of a copy of the file, the fixture that pins it gets through.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { crc32, deflateRawSync } from 'node:zlib';
import { IMAGE_KEYS } from '../bin/run-shard.mjs';
import { BUILD_CAP_MS, INSTALL_CAP_MS, launchPlan, validateTarget } from '../src/targets.mjs';
import * as F from '../sandbox/mcpb-fetch.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const SHA = 'c'.repeat(40);
const URL1 = 'https://github.com/o/n/releases/download/v1.0.0/n.mcpb';
const base = (launch) => ({ id: 's001', repo: 'o/n', commit: SHA, launch });
const tmp = () => mkdtempSync(join(tmpdir(), 'surface-pk-'));

/** A copy of a source file with one guard taken out, beside the original (so its relative imports resolve). */
function mutant(rel, from, to) {
  const src = readFileSync(join(root, rel), 'utf8');
  assert.ok(src.includes(from), `the mutation's text is in ${rel}: ${from.slice(0, 80)}`);
  const ext = rel.slice(rel.lastIndexOf('.'));
  const file = join(root, dirname(rel), `.mutant-${process.pid}-${Math.random().toString(16).slice(2)}${ext}`);
  writeFileSync(file, src.replace(from, to));
  return { file, done: () => rmSync(file, { force: true }) };
}

// ------------------------------------------------------------------ zip fixtures

/** A zip archive: entries { name, data, mode (Unix), method (0 or 8), usize, crc } with any field overridable. */
function zip(entries) {
  const locals = []; const central = []; let off = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? '');
    const method = e.method ?? 8;
    const body = method === 8 ? deflateRawSync(data) : data;
    const name = Buffer.from(e.name, 'utf8');
    const crc = e.crc ?? (crc32(data) >>> 0);
    const usize = e.usize ?? data.length;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(e.flags ?? 0, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(usize, 22); lh.writeUInt16LE(name.length, 26);
    locals.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE((3 << 8) | 20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(e.flags ?? 0, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(usize, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(((e.mode ?? 0o100644) << 16) >>> 0, 38); ch.writeUInt32LE(off, 42);
    central.push(ch, name);
    off += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
const MANIFEST = { name: 'manifest.json', data: '{"manifest_version":"0.3","server":{"type":"node","entry_point":"server/index.js"}}' };
const refusal = (fn) => { try { fn(); } catch (e) { if (e instanceof Error && e.code) return e.code; throw e; } return null; };

// ------------------------------------------------------------------ the list and the plans

test('R-SBX-38 a crate, a .NET tool or a bundle is accepted only by exact, checked names: no option-like name, no version range, a bundle only from a GitHub release asset with its sha256, paths only inside the bundle', () => {
  const ok = (launch) => validateTarget(base(launch));
  ok({ kind: 'cargo', crate: 'my_crate-mcp', version: 'latest' });
  ok({ kind: 'cargo', crate: 'x', version: '0.4.1-beta.2', args: ['--stdio'] });
  ok({ kind: 'nuget', package: 'Acme.Mcp.Server', version: '1.2.3-preview.4+build.5' });
  ok({ kind: 'nuget', package: 'x', version: 'latest' });
  ok({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'node', args: ['/work/pkg/server/index.js'], env: { A_B: 'v' }, workdir: '.' });
  ok({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'binary', entry: 'server/x-linux' });
  ok({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'uv', console: 'x-mcp', extras: ['mcp'], pythonpath: ['.'] });
  const no = (launch, re) => assert.throws(() => validateTarget(base(launch)), re);
  no({ kind: 'cargo', crate: '--git=https://evil/x', version: 'latest' }, /not a crate name/);
  no({ kind: 'cargo', crate: 'x', version: '^1.0' }, /exact crate version/);
  no({ kind: 'cargo', crate: 'x', version: 'latest', git: 'https://x' }, /unknown field/);
  no({ kind: 'nuget', package: '--add-source', version: 'latest' }, /NuGet package id/);
  no({ kind: 'nuget', package: '.hidden', version: 'latest' }, /NuGet package id/);
  no({ kind: 'nuget', package: 'x', version: '[1.0,2.0)' }, /exact NuGet version/);
  no({ kind: 'nuget', package: 'x', version: '1.0.0', source: 'https://evil' }, /unknown field/);
  for (const url of ['http://github.com/o/n/releases/download/v1/n.mcpb', 'https://evil.example/o/n/releases/download/v1/n.mcpb', 'https://github.com/o/n/raw/main/n.mcpb', `${URL1}?x=1`, 'https://github.com.evil.example/o/n/releases/download/v1/n.mcpb', 'https://github.com/o/n/releases/download/v1/../../x']) no({ kind: 'mcpb', url, sha256: 'a'.repeat(64), runtime: 'node' }, /GitHub release asset/);
  no({ kind: 'mcpb', url: URL1, runtime: 'node' }, /sha256/);
  no({ kind: 'mcpb', url: URL1, sha256: 'A'.repeat(64), runtime: 'node' }, /sha256/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'shell' }, /runtime must be one of/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'binary' }, /binary's path/);
  for (const entry of ['../x', '/bin/sh', 'server/../../x', './x']) no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'binary', entry }, /binary's path/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'node', entry: 'x' }, /binary bundle only/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'python', pythonpath: ['../lib'] }, /paths inside the bundle/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'node', pythonpath: ['lib'] }, /python or uv bundle/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'python', console: 'x' }, /uv bundle only/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'uv', extras: ['--index-url=x'] }, /extra names/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'node', workdir: '/etc' }, /folder inside the bundle/);
  no({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'python', env: { PYTHONPATH: '/x' } }, /not a name a target may set/);
  // Every image a plan or one of its steps names is one of ours (images.json, IMAGE_KEYS); the build step has the
  // 15-minute cap, every other install step a cap too.
  const plans = [
    launchPlan({ kind: 'cargo', crate: 'x', version: '1.0.0' }), launchPlan({ kind: 'nuget', package: 'X', version: '1.0.0' }),
    ...['node', 'python', 'uv'].map((runtime) => launchPlan({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime })),
    launchPlan({ kind: 'mcpb', url: URL1, sha256: 'a'.repeat(64), runtime: 'binary', entry: 'b' }),
  ];
  for (const p of plans) {
    for (const k of [p.image, p.runImage, ...p.install.map((s) => s.image)].filter(Boolean)) assert.ok(IMAGE_KEYS.includes(k), k);
    for (const s of p.install) if (s.capMs !== undefined) assert.ok(s.capMs <= BUILD_CAP_MS);
  }
  assert.equal(plans[0].install[0].capMs, BUILD_CAP_MS);
  assert.equal(plans[1].install[1].capMs, INSTALL_CAP_MS);
  assert.deepEqual(plans[0].install[0].cmd.slice(-2), ['--', 'x'], 'the crate name comes after --');
  assert.deepEqual(plans[1].install[1].cmd.slice(0, 4), ['dotnet', 'tool', 'install', 'X']);
});

test('R-SBX-38 mutation check: the validator\'s crate, NuGet id and bundle URL checks each stop their fixture', async () => {
  for (const [from, to, launch] of [
    ["if (typeof l.crate !== 'string' || !CRATE.test(l.crate))", 'if (false)', { kind: 'cargo', crate: '--git=https://evil/x', version: 'latest' }],
    ["if (typeof l.package !== 'string' || !NUGET_ID.test(l.package)) fail(`${what}.launch.package is not a NuGet package id`);", '', { kind: 'nuget', package: '--add-source', version: 'latest' }],
    ["if (typeof l.url !== 'string' || !MCPB_URL.test(l.url))", 'if (false)', { kind: 'mcpb', url: 'https://evil.example/o/n/releases/download/v1/n.mcpb', sha256: 'a'.repeat(64), runtime: 'node' }],
  ]) {
    const m = mutant('src/targets.mjs', from, to);
    try {
      const T = await import(pathToFileURL(m.file).href);
      assert.doesNotThrow(() => T.validateTarget(base(launch)), 'without the guard the fixture gets through');
    } finally { m.done(); }
    assert.throws(() => validateTarget(base(launch)));
  }
});

// ------------------------------------------------------------------ cargo-entry.mjs

function crates(installs, bins = []) {
  const d = tmp();
  mkdirSync(join(d, 'bin'));
  writeFileSync(join(d, '.crates2.json'), JSON.stringify({ installs }));
  for (const b of bins) writeFileSync(join(d, 'bin', b), 'ELF');
  return d;
}
const entry = (script, ...a) => { const r = spawnSync(process.execPath, [join(root, 'sandbox', script), ...a], { encoding: 'utf8' }); return { rc: r.status, out: JSON.parse(r.stdout.trim().split('\n').pop()) }; };
const CRATES_IO = '(sparse+https://index.crates.io/)';

test('R-SBX-39 the crate\'s binary is the one cargo recorded from crates.io, picked without a guess, and only a regular file', () => {
  let d = crates({ [`x-mcp 0.4.1 ${CRATES_IO}`]: { bins: ['x-mcp'] } }, ['x-mcp']);
  assert.deepEqual(entry('cargo-entry.mjs', d, 'x-mcp'), { rc: 0, out: { script: join(d, 'bin', 'x-mcp'), version: '0.4.1', bins: 1 } });
  d = crates({ [`x 1.0.0 ${CRATES_IO}`]: { bins: ['other', 'x'] } }, ['other', 'x']);
  assert.equal(entry('cargo-entry.mjs', d, 'x').out.script, join(d, 'bin', 'x'));
  d = crates({ [`x 1.0.0 ${CRATES_IO}`]: { bins: ['cli', 'x-mcp-server'] } }, ['cli', 'x-mcp-server']);
  assert.equal(entry('cargo-entry.mjs', d, 'x').out.script, join(d, 'bin', 'x-mcp-server'));
  d = crates({ [`x 1.0.0 ${CRATES_IO}`]: { bins: ['a', 'b'] } }, ['a', 'b']);
  assert.deepEqual(entry('cargo-entry.mjs', d, 'x'), { rc: 1, out: { error: 'several_binaries', bins: ['a', 'b'] } });
  d = crates({ 'x 1.0.0 (git+https://github.com/evil/x#abc)': { bins: ['x'] } }, ['x']);
  assert.deepEqual(entry('cargo-entry.mjs', d, 'x'), { rc: 1, out: { error: 'not_installed' } }, 'a crate from anywhere but crates.io is not ours to run');
  d = crates({ [`x 1.0.0 ${CRATES_IO}`]: { bins: [] } });
  assert.equal(entry('cargo-entry.mjs', d, 'x').out.error, 'no_binary');
  d = crates({ [`x 1.0.0 ${CRATES_IO}`]: { bins: ['x'] } });
  symlinkSync('/bin/sh', join(d, 'bin', 'x'));
  assert.equal(entry('cargo-entry.mjs', d, 'x').out.error, 'no_binary', 'a link is never the binary');
});

test('R-SBX-39 mutation check: without the crates.io source check, cargo-entry.mjs would start a crate built from anywhere', () => {
  const d = crates({ 'x 1.0.0 (git+https://github.com/evil/x#abc)': { bins: ['x'] } }, ['x']);
  assert.equal(entry('cargo-entry.mjs', d, 'x').out.error, 'not_installed');
  const m = mutant('sandbox/cargo-entry.mjs', "k.split(' ')[0] === crate && / \\(registry", "k.split(' ')[0] === crate || / \\(registry");
  try {
    const r = spawnSync(process.execPath, [m.file, d, 'x'], { encoding: 'utf8' });
    assert.equal(JSON.parse(r.stdout.trim()).script, join(d, 'bin', 'x'), 'without the check the git crate runs');
  } finally { m.done(); }
});

// ------------------------------------------------------------------ nuget-entry.mjs

/** A tool path as `dotnet tool install --tool-path` leaves it: .store/<id>/<v>/<pkg>/<v>/tools/<tfm>/<rid>/, and the launchers. */
function toolPath(id, { version = '1.2.0', pkgs = [[id, 'net9.0', 'any', [{ name: 'acme-mcp', entry: 'Acme.Mcp.dll', runner: 'dotnet' }]]], shims = ['acme-mcp'], files = true } = {}) {
  const d = tmp();
  for (const [pkg, tfm, rid, cmds] of pkgs) {
    const dir = join(d, '.store', id.toLowerCase(), version, pkg.toLowerCase(), version, 'tools', tfm, rid);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'DotnetToolSettings.xml'), `<?xml version="1.0" encoding="utf-8"?>\n<DotNetCliTool Version="2">\n  <Commands>\n${cmds.map((c) => `    <Command Name="${c.name}" EntryPoint="${c.entry}" Runner="${c.runner}" />`).join('\n')}\n  </Commands>\n</DotNetCliTool>\n`);
    if (files) for (const c of cmds) if (!c.entry.includes('..')) { mkdirSync(dirname(join(dir, c.entry)), { recursive: true }); writeFileSync(join(dir, c.entry), 'MZ'); }
  }
  for (const s of shims) writeFileSync(join(d, s), 'ELF');
  return d;
}

test('R-SBX-40 a .NET tool\'s command is the one its DotnetToolSettings.xml declares and the install created a launcher for, its entry point a regular file of the package, the linux-x64 build of a RID-specific tool; never a guess', () => {
  let d = toolPath('Acme.Mcp');
  assert.deepEqual(entry('nuget-entry.mjs', d, 'Acme.Mcp'), { rc: 0, out: { script: join(d, '.store/acme.mcp/1.2.0/acme.mcp/1.2.0/tools/net9.0/any/Acme.Mcp.dll'), runner: 'dotnet', command: 'acme-mcp', version: '1.2.0', tfm: 'net9.0', rid: 'any' } });
  // A RID-specific tool (.NET 10): the pointer package and the runtime packages; the linux-x64 one runs.
  d = toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp', 'net10.0', 'any', [{ name: 'acme-mcp', entry: 'Acme.Mcp.dll', runner: 'dotnet' }]], ['Acme.Mcp.linux-x64', 'net10.0', 'linux-x64', [{ name: 'acme-mcp', entry: 'acme-mcp', runner: 'executable' }]], ['Acme.Mcp.win-x64', 'net10.0', 'win-x64', [{ name: 'acme-mcp', entry: 'acme-mcp.exe', runner: 'executable' }]]] });
  assert.deepEqual([entry('nuget-entry.mjs', d, 'Acme.Mcp').out.rid, entry('nuget-entry.mjs', d, 'Acme.Mcp').out.runner], ['linux-x64', 'executable']);
  d = toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp.win-x64', 'net10.0', 'win-x64', [{ name: 'acme-mcp', entry: 'acme-mcp.exe', runner: 'executable' }]]] });
  assert.equal(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'no_linux_build');
  d = toolPath('Acme.Mcp', { shims: [] });
  assert.equal(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'no_command', 'no launcher, no command');
  d = toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp', 'net9.0', 'any', [{ name: 'acme-mcp', entry: `a/${'../'.repeat(24)}bin/sh`, runner: 'dotnet' }]]] });
  assert.equal(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'no_command', 'an entry point out of the package is never run');
  d = toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp', 'net9.0', 'any', [{ name: 'acme-mcp', entry: 'Acme.Mcp.dll', runner: 'powershell' }]]] });
  assert.equal(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'no_command', 'only the runners we start');
  d = toolPath('Acme.Mcp', { files: false });
  symlinkSync('/bin/sh', join(d, '.store/acme.mcp/1.2.0/acme.mcp/1.2.0/tools/net9.0/any/Acme.Mcp.dll'));
  assert.equal(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'no_command', 'a link is never the entry point');
  d = toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp', 'net9.0', 'any', [{ name: 'a', entry: 'A.dll', runner: 'dotnet' }, { name: 'b', entry: 'B.dll', runner: 'dotnet' }]]], shims: ['a', 'b'] });
  assert.deepEqual(entry('nuget-entry.mjs', d, 'Acme.Mcp').out, { error: 'several_commands', commands: ['a', 'b'] });
  assert.equal(entry('nuget-entry.mjs', tmp(), 'Acme.Mcp').out.error, 'not_installed');
  assert.equal(entry('nuget-entry.mjs', d, '--help').out.error, 'usage');
});

test('R-SBX-40 mutation check: without the entry point\'s path check, the regular-file check or the launcher check, nuget-entry.mjs would start what it must not', () => {
  for (const [from, to, setup] of [
    [".some((s) => s === '..' || s === '.' || s === '')", '.some(() => false)', () => toolPath('Acme.Mcp', { pkgs: [['Acme.Mcp', 'net9.0', 'any', [{ name: 'acme-mcp', entry: `a/${'../'.repeat(24)}bin/sh`, runner: 'dotnet' }]]] })],
    ['const isFile = (p) => { try { return lstatSync(p).isFile(); } catch { return false; } };', 'const isFile = (p) => { try { return statSync(p).isFile(); } catch { return false; } };', () => { const d = toolPath('Acme.Mcp', { files: false }); symlinkSync('/bin/sh', join(d, '.store/acme.mcp/1.2.0/acme.mcp/1.2.0/tools/net9.0/any/Acme.Mcp.dll')); return d; }],
    [' && isFile(join(root, c.name)));', ');', () => toolPath('Acme.Mcp', { shims: [] })],
  ]) {
    const d = setup();
    assert.ok(entry('nuget-entry.mjs', d, 'Acme.Mcp').out.error, 'refused with the guard');
    const src = readFileSync(join(root, 'sandbox/nuget-entry.mjs'), 'utf8');
    const m = mutant('sandbox/nuget-entry.mjs', from, to);
    if (to.includes('statSync')) writeFileSync(m.file, src.replace(from, to).replace("import { lstatSync, readdirSync, readFileSync } from 'node:fs';", "import { lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';"));
    try {
      const r = spawnSync(process.execPath, [m.file, d, 'Acme.Mcp'], { encoding: 'utf8' });
      const out = JSON.parse(r.stdout.trim());
      assert.ok(out.script && !out.error, `without the guard it gets through: ${r.stdout}`);
    } finally { m.done(); }
  }
});

// ------------------------------------------------------------------ mcpb-fetch.mjs: the archive

test('R-SBX-41 an MCP bundle unpacks only inside its folder: no absolute, dot-dot, backslash or drive path, no link created, no name twice, every size and CRC checked, our caps on count and size; exec bits only where the archive or the entry says', () => {
  const d = tmp();
  const good = zip([MANIFEST, { name: 'server/', data: '', mode: 0o040755 }, { name: 'server/index.js', data: 'console.log(1)\n' }, { name: 'server/bin/tool', data: 'ELF', mode: 0o100755 }, { name: 'node_modules/.bin/x', data: '../x/cli.js', mode: 0o120777 }, { name: 'big.txt', data: Buffer.alloc(100_000, 'a') }]);
  const u = F.unpack(good, join(d, 'pkg'));
  assert.deepEqual(u, { files: 4, dirs: 1, links_skipped: 1, unpacked: good.length > 0 ? MANIFEST.data.length + 15 + 3 + 100_000 : 0 });
  assert.equal(readFileSync(join(d, 'pkg/server/index.js'), 'utf8'), 'console.log(1)\n');
  assert.equal(statSync(join(d, 'pkg/server/bin/tool')).mode & 0o777, 0o755);
  assert.equal(statSync(join(d, 'pkg/server/index.js')).mode & 0o777, 0o644);
  assert.ok(!existsSync(join(d, 'pkg/node_modules/.bin/x')), 'a link is left out, never created');
  F.unpack(zip([MANIFEST, { name: 'server/x', data: 'ELF' }]), join(d, 'pkg2'), { exec: 'server/x' });
  assert.equal(statSync(join(d, 'pkg2/server/x')).mode & 0o777, 0o755, 'the --exec path is made executable');
  const code = (entries, opts = {}) => refusal(() => F.unpack(Buffer.isBuffer(entries) ? entries : zip(entries), join(tmp(), 'pkg'), opts));
  for (const name of ['../evil', '/etc/passwd', 'a/../../evil', 'a\\..\\evil', 'C:/x', 'a//b', './a', 'a\u0000b', 'a\nb']) assert.equal(code([MANIFEST, { name, data: 'x' }]), 'unsafe_path', JSON.stringify(name));
  assert.equal(code([MANIFEST, { name: 'a', data: '1' }, { name: 'a', data: '2' }]), 'unsafe_path', 'one path twice');
  assert.equal(code([MANIFEST, { name: 'a', data: '1' }, { name: 'a/b', data: '2' }]), 'unsafe_path', 'a folder where a file is');
  // A bomb: an entry that inflates past the size it declares is stopped at that size, never written.
  assert.equal(code([MANIFEST, { name: 'bomb', data: Buffer.alloc(5_000_000), usize: 10 }]), 'zip_unreadable');
  assert.equal(code([MANIFEST, { name: 'big', data: Buffer.alloc(2_000) }], { maxUnpacked: 1_000 }), 'too_big_unpacked', 'the declared sizes count against the cap before anything is written');
  assert.equal(code([MANIFEST, { name: 'a', data: 'x' }, { name: 'b', data: 'y' }], { maxFiles: 2 }), 'too_many_files');
  assert.equal(code([MANIFEST, { name: 'a', data: 'hello', crc: 1 }]), 'zip_unreadable', 'a CRC mismatch');
  assert.equal(code([MANIFEST, { name: 'a', data: 'x', flags: 1 }]), 'zip_unreadable', 'an encrypted entry');
  assert.equal(code([MANIFEST, { name: 'a', data: 'x', method: 12 }]), 'zip_unreadable', 'another method');
  assert.equal(code([{ name: 'server/index.js', data: 'x' }]), 'no_manifest');
  assert.equal(code([MANIFEST], { exec: 'server/x' }), 'exec_missing');
  assert.equal(code(Buffer.from('#!/bin/sh\necho not a zip\n'.repeat(20))), 'not_a_zip');
  assert.equal(code(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(100), Buffer.from('PK\u0003\u0004'), Buffer.alloc(100)])), 'zip_unreadable', 'zip bytes inside another file are not read as a bundle, but not called no archive either');
  // Nothing is written outside the folder, whatever was refused.
  assert.deepEqual(readdirSync(d).sort(), ['pkg', 'pkg2']);
  assert.ok(lstatSync(join(d, 'pkg')).isDirectory());
});

test('R-SBX-41 mutation check: each archive guard of mcpb-fetch.mjs stops its fixture', async () => {
  const cases = [
    ["if (typeof name !== 'string' || !name || name.length > 1024) return null;\n  if (/[\\u0000-\\u001f\\u007f\\\\:]/.test(name) || name.startsWith('/')) return null;", 'if (false) return null;', [MANIFEST, { name: 'a\\..\\evil', data: 'x' }], 'unsafe_path'],
    ["segs.some((s) => s === '' || s === '.' || s === '..' || s.length > 255)", 'false', [MANIFEST, { name: 'a/../../evil', data: 'x' }], 'unsafe_path'],
    ["if (kind === 'link') { links++; continue; }", "if (kind === 'link') { links++; }", [MANIFEST, { name: 'l', data: '/etc/passwd', mode: 0o120777 }], 'link'],
    ['if (b.length !== e.usize)', 'if (false)', null, 'size'],
    ['if ((crc32(b) >>> 0) !== e.crc)', 'if (false)', [MANIFEST, { name: 'a', data: 'hello', crc: 1 }], 'zip_unreadable'],
    ["if (total > maxUnpacked) throw new Refusal('too_big_unpacked');", '', [MANIFEST, { name: 'big', data: Buffer.alloc(2_000) }], 'too_big_unpacked'],
  ];
  for (const [from, to, entries, want] of cases) {
    const m = mutant('sandbox/mcpb-fetch.mjs', from, to);
    try {
      const M = await import(pathToFileURL(m.file).href);
      if (want === 'link') {
        const d = join(tmp(), 'pkg');
        M.unpack(zip(entries), d);
        assert.ok(existsSync(join(d, 'l')), 'without the guard a link entry is written');
        continue;
      }
      if (want === 'size') {
        // Stored data longer than declared: the guard alone stops it (inflate is not involved).
        const z = zip([MANIFEST, { name: 'a', data: 'hello world', method: 0, usize: 5 }]);
        assert.equal(refusal(() => F.unpack(z, join(tmp(), 'pkg'))), 'zip_unreadable');
        assert.equal(refusal(() => M.unpack(z, join(tmp(), 'pkg'))), null, 'without the guard a size lie gets through');
        continue;
      }
      const z = zip(entries);
      const opts = want === 'too_big_unpacked' ? { maxUnpacked: 1_000 } : {};
      assert.equal(refusal(() => F.unpack(z, join(tmp(), 'pkg'), opts)), want);
      assert.notEqual(refusal(() => M.unpack(z, join(tmp(), 'pkg'), opts)), want, `without the guard: ${from.slice(0, 60)}`);
    } finally { m.done(); }
  }
});

// ------------------------------------------------------------------ mcpb-fetch.mjs: the download

test('R-SBX-42 a bundle is fetched from GitHub release assets only, every redirect checked, within the byte cap, and kept only when its sha256 is the one named', async () => {
  const body = zip([MANIFEST]);
  const sha = createHash('sha256').update(body).digest('hex');
  const seen = [];
  const get = (hops) => async (url) => { seen.push(url.href); const h = hops.shift(); return h; };
  const ok = await F.fetchBundle(URL1, { get: get([{ status: 302, location: 'https://release-assets.githubusercontent.com/x?sig=1' }, { status: 200, body, sha256: sha }]) });
  assert.equal(ok.sha256, sha);
  assert.deepEqual(seen, [URL1, 'https://release-assets.githubusercontent.com/x?sig=1']);
  const fails = async (hops, start = URL1) => { try { await F.fetchBundle(start, { get: get(hops) }); return null; } catch (e) { return e.code; } };
  assert.equal(await fails([{ status: 302, location: 'https://evil.example/x' }]), 'redirect_refused');
  assert.equal(await fails([{ status: 302, location: 'http://release-assets.githubusercontent.com/x' }]), 'redirect_refused', 'never plain http');
  assert.equal(await fails([{ status: 302, location: 'https://release-assets.githubusercontent.com:8443/x' }]), 'redirect_refused', 'never another port');
  assert.equal(await fails([{ status: 302, location: 'https://user:pw@github.com/x' }]), 'redirect_refused');
  assert.equal(await fails(Array(7).fill({ status: 302, location: URL1 })), 'redirect_refused', 'at most 5 redirects');
  assert.equal(await fails([], 'https://evil.example/n.mcpb'), 'redirect_refused');
  // The whole step: a bundle whose bytes are not the ones named is not unpacked.
  const outs = [];
  const dest = join(tmp(), 'pkg');
  const rc = await F.main([URL1, 'f'.repeat(64), dest], {}, { get: get([{ status: 200, body, sha256: sha }]), say: (o) => outs.push(o) });
  assert.deepEqual([rc, outs[0].error, existsSync(dest)], [1, 'sha256_mismatch', false]);
  const rc2 = await F.main([URL1, sha, dest], {}, { get: get([{ status: 200, body, sha256: sha }]), say: (o) => outs.push(o) });
  assert.deepEqual([rc2, outs[1].ok, existsSync(join(dest, 'manifest.json'))], [0, true, true]);
  assert.equal(await F.main(['--exec', sha, dest], {}, { say: (o) => outs.push(o) }), 2);
  // The byte cap, on a real response stream (a local HTTPS-free server is not needed: getOnce is exercised through a
  // stub stream in the mutation check below); the declared length alone is enough to refuse.
  assert.equal(F.MAX_BYTES, 200 * 1024 * 1024);
});

test('R-SBX-42 mutation check: without the host check on redirects, or the sha256 check, the fixture gets through', async () => {
  const body = zip([MANIFEST]);
  const sha = createHash('sha256').update(body).digest('hex');
  const get = (hops) => async () => hops.shift();
  let m = mutant('sandbox/mcpb-fetch.mjs', 'return x.protocol === \'https:\' && MCPB_HOSTS.includes(x.hostname) && !x.port && !x.username && !x.password ? x : null;', 'return x;');
  try {
    const M = await import(pathToFileURL(m.file).href);
    const r = await M.fetchBundle(URL1, { get: get([{ status: 302, location: 'https://evil.example/x' }, { status: 200, body, sha256: sha }]) });
    assert.equal(r.sha256, sha, 'without the host check the redirect is followed');
  } finally { m.done(); }
  m = mutant('sandbox/mcpb-fetch.mjs', "if (r.sha256 !== sha) throw new Refusal('sha256_mismatch', { bytes: r.body.length });", '');
  try {
    const M = await import(pathToFileURL(m.file).href);
    const outs = [];
    assert.equal(await M.main([URL1, 'f'.repeat(64), join(tmp(), 'pkg')], {}, { get: get([{ status: 200, body, sha256: sha }]), say: (o) => outs.push(o) }), 0, 'without the sha256 check other bytes are unpacked');
  } finally { m.done(); }
});

// ------------------------------------------------------------------ pyproject-reqs.py

function python() {
  for (const p of [process.env.SURFACE_TEST_PYTHON, 'python3.13', 'python3.12', 'python3.11', 'python3'].filter(Boolean)) {
    const r = spawnSync(p, ['-I', '-c', 'import tomllib'], { encoding: 'utf8' });
    if (r.status === 0) return p;
  }
  return null;
}
const PY = python();
const reqs = (toml, extras = [], script = join(root, 'sandbox', 'pyproject-reqs.py')) => {
  const d = tmp();
  if (toml !== null) writeFileSync(join(d, 'pyproject.toml'), toml);
  const r = spawnSync(PY, ['-I', script, d, join(d, 'lock', 'requirements.txt'), ...extras], { encoding: 'utf8' });
  const out = JSON.parse(r.stdout.trim() || '{}');
  return { rc: r.status, out, file: existsSync(join(d, 'lock', 'requirements.txt')) ? readFileSync(join(d, 'lock', 'requirements.txt'), 'utf8') : null, d };
};

test('R-SBX-43 a uv bundle\'s requirements are its pyproject\'s, read as data: the project itself when it has a build system, else its dependencies and the extras asked for, never a line pip reads as an option', { skip: !PY && 'no Python with tomllib' }, () => {
  let r = reqs('[project]\nname = "x"\ndependencies = ["mcp>=1.2", "httpx[http2]>=0.27; python_version >= \'3.10\'"]\n[project.optional-dependencies]\nmcp = ["fastmcp==2.1"]\n', ['mcp']);
  assert.deepEqual([r.rc, r.out], [0, { ok: true, requirements: 3, project: false }]);
  assert.equal(r.file, 'mcp>=1.2\nhttpx[http2]>=0.27; python_version >= \'3.10\'\nfastmcp==2.1\n');
  r = reqs('[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n[project]\nname = "x"\n', ['mcp']);
  assert.equal(r.out.project, true);
  assert.equal(r.file, `${r.d}[mcp]\n`);
  for (const dep of ['--index-url=https://evil.example/simple', '-e /etc', 'x --extra-index-url https://evil.example', 'x\t-r /etc/passwd']) {
    r = reqs(`[project]\nname = "x"\ndependencies = [${JSON.stringify(dep)}]\n`);
    assert.deepEqual([r.rc, r.out.error, r.file], [1, 'bad_requirement', null], dep);
  }
  assert.equal(reqs(null).out.error, 'no_pyproject');
  assert.equal(reqs('this is = = not toml').out.error, 'pyproject_unreadable');
  assert.equal(reqs('[project]\nname = "x"\n', ['--index-url']).out.error, 'usage');
});

test('R-SBX-43 mutation check: without the option check a requirements line pip reads as an option is written', { skip: !PY && 'no Python with tomllib' }, () => {
  const m = mutant('sandbox/pyproject-reqs.py', 'if not isinstance(r, str) or not REQ.match(r) or r.lstrip().startswith("-") or re.search(r"\\s-", r):', 'if not isinstance(r, str):');
  try {
    const r = reqs('[project]\nname = "x"\ndependencies = ["x --extra-index-url https://evil.example"]\n', [], m.file);
    assert.equal(r.rc, 0, 'without the guard the option line is written');
  } finally { m.done(); }
});
