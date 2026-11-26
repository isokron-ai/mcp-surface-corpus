#!/usr/bin/env node
/**
 * The entry of a crate installed with `cargo install --root <root>` (src/targets.mjs launchPlan, kind cargo): which of its binaries is the
 * server, and the version cargo resolved. Ours, from the read-only tools volume; it runs in an install container (the node image) after
 * the build, reads <root>/.crates2.json (cargo's own record of what it installed) and lists <root>/bin, and treats both
 * as data.
 *
 *   node cargo-entry.mjs <root> <crate>
 *
 * Prints one line, { script, version, bins } where script is <root>/bin/<name>, and exits 0; or { error } and exits 1:
 *   not_installed   cargo recorded no install of <crate>
 *   no_binary       the crate installed no binary
 *   several_binaries  more than one binary and none is named for the crate or for MCP (we would have to guess)
 * The binary is: the only one; else the one named like the crate; else the only one whose name says mcp.
 *
 * The same rules, codes and output as isokron-ai/mcp-writecheck-action loop/sandbox/cargo-entry.mjs (its crate path,
 * WC14), so both lanes start the same binary of the same crate.
 */
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const [root, crate] = process.argv.slice(2);
const out = (o, code) => { process.stdout.write(`${JSON.stringify(o)}\n`); process.exit(code); };
const BIN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;
if (!root || !/^\/[A-Za-z0-9._/-]{1,200}$/.test(root) || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(crate ?? '')) out({ error: 'usage' }, 2);

function pickBinary(crateName, bins) {
  const ok = [...new Set(bins.filter((b) => typeof b === 'string' && BIN.test(b)))].sort();
  if (ok.length === 0) return { error: 'no_binary' };
  if (ok.length === 1) return { bin: ok[0] };
  const norm = (s) => s.toLowerCase().replace(/_/g, '-');
  const named = ok.filter((b) => norm(b) === norm(crateName));
  if (named.length === 1) return { bin: named[0] };
  const mcp = ok.filter((b) => /mcp/i.test(b));
  if (mcp.length === 1) return { bin: mcp[0] };
  return { error: 'several_binaries' };
}

let doc;
try { doc = JSON.parse(readFileSync(join(root, '.crates2.json'), 'utf8')); } catch { out({ error: 'not_installed' }, 1); }
// cargo's key: "<name> <version> (<source>)"; the crate from crates.io only.
const key = Object.keys(doc?.installs ?? {}).find((k) => k.split(' ')[0] === crate && / \(registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index\)$|\(sparse\+https:\/\/index\.crates\.io\/\)$/.test(k));
if (!key) out({ error: 'not_installed' }, 1);
const version = key.split(' ')[1];
const bins = Array.isArray(doc.installs[key]?.bins) ? doc.installs[key].bins : [];
const pick = pickBinary(crate, bins);
if (pick.error) out({ error: pick.error, bins: bins.filter((b) => typeof b === 'string' && BIN.test(b)).slice(0, 20) }, 1);
const script = join(root, 'bin', pick.bin);
try { if (!lstatSync(script).isFile()) out({ error: 'no_binary' }, 1); } catch { out({ error: 'no_binary' }, 1); }
out({ script, version: /^[0-9A-Za-z.+-]{1,64}$/.test(version ?? '') ? version : null, bins: bins.length }, 0);
