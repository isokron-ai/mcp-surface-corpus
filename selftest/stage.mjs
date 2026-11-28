#!/usr/bin/env node
// A later stage of the sandbox self test: our code, in a helper container of bin/sandbox-selftest.mjs,
// run after a hostile case's container ended or was torn down, to see what the case left behind.
// It prints one JSON line and nothing else.
//
//   node stage.mjs reach HOST PORT UDS_PATH ABSTRACT_NAME
//       tries what unix-socket left listening: TCP HOST:PORT on the run network, the unix socket it
//       bound in the work volume, and its abstract socket; { reach: [{ to, ok, code, bytes }] }
//   node stage.mjs grow MS PATH...
//       the size of each file, then again MS later: whether something still writes them
//       (background's heartbeats); { grow: [{ path, before, after }] }
//   node stage.mjs exists PATH...
//       whether each path exists (links not followed); { exists: { path: true|false } }
//   node stage.mjs measure DIR
//       the filesystem DIR (the work volume, mounted read-only) lives on, as statfs gives it, and how
//       much of it is used; { disk: { work_fs_mb, work_fs_inodes, work_used_mb, work_files } }
//   node stage.mjs tree DIR
//       every entry under DIR (links not followed: a link is its target as written), with its kind, mode,
//       owner, group, link count, size and the sha256 of a file's bytes, and one digest over them all (work-overlay: the work volume
//       under a layer, before and after the case); { tree: { entries, sha256, items: [[path, sha256]] } }
//   node stage.mjs layer DIR PATH...
//       measure DIR (a layer's upper volume, read-only) and whether each PATH exists in it (links not
//       followed); { disk: {...}, exists: { path: true|false } }
import { createHash } from 'node:crypto';
import { readdirSync, lstatSync, readFileSync, readlinkSync, statfsSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { connect } from 'node:net';
import { join } from 'node:path';

const say = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);

/** One connection: ok only when it connected and the other end said something. */
export function tryConnect(opts, label, ms = 4000) {
  return new Promise((done) => {
    let bytes = 0; let connected = false; let finished = false;
    const end = (code) => { if (finished) return; finished = true; clearTimeout(t); s.destroy(); done({ to: label, ok: connected && bytes > 0, code, bytes }); };
    const s = connect(opts);
    const t = setTimeout(() => end(connected ? 'no answer' : 'timeout'), ms);
    s.on('connect', () => { connected = true; });
    s.on('data', (b) => { bytes += b.length; end('answered'); });
    s.on('error', (e) => end(String(e.code || e.message).slice(0, 20)));
    s.on('close', () => end(connected ? 'closed' : 'closed before connecting'));
  });
}

/** statfs of a folder, and what is in it (bounded walk, links not followed). */
export function measure(dir, { maxEntries = 200_000, statfs = statfsSync } = {}) {
  const st = statfs(dir);
  let files = 0; let bytes = 0; const stack = [dir];
  while (stack.length && files < maxEntries) {
    const d = stack.pop();
    let names = [];
    try { names = readdirSync(d); } catch { continue; }
    for (const n of names) {
      files++;
      try { const l = lstatSync(join(d, n)); if (l.isDirectory()) stack.push(join(d, n)); else bytes += l.blocks * 512; } catch { /* gone */ }
      if (files >= maxEntries) break;
    }
  }
  const mb = (n) => Math.round(Number(n) / 1048576);
  return { work_fs_mb: mb(Number(st.blocks) * Number(st.bsize)), work_fs_inodes: Number(st.files), work_used_mb: mb((Number(st.blocks) - Number(st.bfree)) * Number(st.bsize)), work_files: files, work_bytes_mb: mb(bytes) };
}

const sha = (b) => createHash('sha256').update(b).digest('hex');
const there = (p) => { try { lstatSync(p); return true; } catch { return false; } };

/** One entry of a tree: kind, mode, owner, group, link count, then a file's size and digest or a link's target. */
export function entryOf(l, extra = '') {
  const kind = l.isSymbolicLink() ? 'l' : l.isDirectory() ? 'd' : l.isFile() ? 'f' : `o${l.mode >>> 12}`;
  const head = `${kind} ${(l.mode & 0o7777).toString(8)} ${l.uid}:${l.gid} ${l.nlink}`;
  return kind === 'f' ? `${head} ${l.size} ${extra}` : kind === 'l' ? `${head} ${extra}` : head;
}

/** Every entry under a folder, bounded, links not followed; one digest over the sorted entries. */
export function tree(dir, { maxEntries = 20_000, maxFile = 16 * 1024 * 1024, maxItems = 2000 } = {}) {
  const items = []; const stack = [''];
  while (stack.length && items.length < maxEntries) {
    const rel = stack.pop();
    let names = [];
    try { names = readdirSync(join(dir, rel)).sort(); } catch (e) { items.push([rel || '.', `unreadable ${e.code || 'error'}`]); continue; }
    for (const n of names) {
      const r = rel ? `${rel}/${n}` : n; const p = join(dir, r);
      let l; try { l = lstatSync(p); } catch (e) { items.push([r, `gone ${e.code || 'error'}`]); continue; }
      let extra = '';
      if (l.isSymbolicLink()) { try { extra = readlinkSync(p); } catch { extra = '?'; } } else if (l.isDirectory()) stack.push(r); else if (l.isFile() && l.size <= maxFile) { try { extra = sha(readFileSync(p)); } catch (e) { extra = `unreadable ${e.code || 'error'}`; } } else if (l.isFile()) extra = 'big';
      items.push([r, entryOf(l, extra)]);
      if (items.length >= maxEntries) break;
    }
  }
  items.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return { entries: items.length, sha256: sha(JSON.stringify(items)), items: items.slice(0, maxItems).map(([p, x]) => [p.slice(0, 200), sha(x)]) };
}

async function main(argv) {
  if (argv[0] === 'reach' && argv.length === 5) {
    const [, host, port, uds, abs] = argv;
    const reach = [];
    reach.push(await tryConnect({ host, port: Number(port) }, `tcp ${host}:${port}`));
    reach.push(await tryConnect({ path: uds }, `unix ${uds}`));
    reach.push(await tryConnect({ path: `\0${abs}` }, `abstract @${abs}`));
    say({ reach });
    return 0;
  }
  if (argv[0] === 'measure' && argv.length === 2) { say({ disk: measure(argv[1]) }); return 0; }
  if (argv[0] === 'grow' && argv.length >= 3 && /^\d{1,5}$/.test(argv[1])) {
    const size = (p) => { try { return lstatSync(p).size; } catch { return -1; } };
    const paths = argv.slice(2);
    const before = paths.map(size);
    await sleep(Number(argv[1]));
    say({ grow: paths.map((path, i) => ({ path, before: before[i], after: size(path) })) });
    return 0;
  }
  if (argv[0] === 'tree' && argv.length === 2) { say({ tree: tree(argv[1]) }); return 0; }
  if (argv[0] === 'layer' && argv.length >= 3) { say({ disk: measure(argv[1]), exists: Object.fromEntries(argv.slice(2).map((p) => [p, there(p)])) }); return 0; }
  if (argv[0] === 'exists' && argv.length >= 2) {
    say({ exists: Object.fromEntries(argv.slice(1).map((p) => [p, there(p)])) });
    return 0;
  }
  process.stderr.write('usage: stage.mjs reach HOST PORT UDS ABSTRACT | measure DIR | tree DIR | layer DIR PATH... | grow MS PATH... | exists PATH...\n');
  return 2;
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).then((rc) => { process.exitCode = rc; });
