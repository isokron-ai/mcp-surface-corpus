#!/usr/bin/env node
/**
 * Runs in the install container after `npm install --prefix <prefix> <package>`. Reads the
 * installed package's own package.json (data, never executed) and prints the script its bin points
 * at, so the server can be started as `node <script>` without npx, a shell or a PATH lookup.
 *
 *   node npm-entry.mjs <prefix> <package> [bin name]
 *
 * Prints { script, bin, version, engines, type }. The script path must stay inside the package.
 */
import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';

const [prefix, pkg, want] = process.argv.slice(2);
const die = (m) => { process.stdout.write(`${JSON.stringify({ error: m })}\n`); process.exit(1); };
if (!prefix || !pkg) die('usage: npm-entry.mjs <prefix> <package> [bin]');
const dir = join(prefix, 'node_modules', ...pkg.split('/'));
let j;
try { j = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')); } catch (e) { die(`the installed package has no readable package.json: ${String(e.code || e.message).slice(0, 80)}`); }
let bin = null; let rel = null;
if (typeof j.bin === 'string') { bin = String(j.name || pkg).split('/').pop(); rel = j.bin; } else if (j.bin && typeof j.bin === 'object') {
  const names = Object.keys(j.bin);
  // With several bins, the server is the one whose name says mcp or server: the bin named like the package is often
  // its CLI (return_rp ships return_rp and return_rp-mcp). The package's own name still wins when it says so too.
  const own = names.find((n) => n === String(j.name || '').split('/').pop());
  const server = names.filter((n) => /mcp|server/i.test(n));
  bin = want && names.includes(want) ? want : want ? null : names.length === 1 ? names[0] : (own && /mcp|server/i.test(own) ? own : server[0] ?? own ?? names[0] ?? null);
  if (bin) rel = j.bin[bin];
}
if (!rel && !want && typeof j.main === 'string') rel = j.main;
if (typeof rel !== 'string' || !rel) die(want ? 'the package has no bin of that name' : 'the package declares no bin');
let real; let root;
try { root = realpathSync(dir); real = realpathSync(resolve(dir, rel)); } catch { die('the bin script is not in the package'); }
if (!(real === root || real.startsWith(root + sep))) die('the bin script points outside the package');
process.stdout.write(`${JSON.stringify({ script: real, bin, version: typeof j.version === 'string' ? j.version.slice(0, 64) : null, engines: j.engines && typeof j.engines.node === 'string' ? j.engines.node.slice(0, 64) : null, type: j.type === 'module' ? 'module' : 'commonjs' })}\n`);
