#!/usr/bin/env node
// A later stage of the sandbox self test: our code, in a helper container of bin/sandbox-selftest.mjs,
// run after a hostile case's container ended or was torn down, to see what the case left behind.
// It prints one JSON line and nothing else.
//
//   node stage.mjs reach HOST PORT UDS_PATH ABSTRACT_NAME
//       tries what unix-socket left listening: TCP HOST:PORT on the run network, the unix socket it
//       bound in the work volume, and its abstract socket; { reach: [{ to, ok, code, bytes }] }
//   node stage.mjs measure DIR
//       the filesystem DIR (the work volume, mounted read-only) lives on, as statfs gives it, and how
//       much of it is used; { disk: { work_fs_mb, work_fs_inodes, work_used_mb, work_files } }
import { readdirSync, lstatSync, statfsSync } from 'node:fs';
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
  process.stderr.write('usage: stage.mjs reach HOST PORT UDS ABSTRACT | measure DIR\n');
  return 2;
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2)).then((rc) => { process.exitCode = rc; });
