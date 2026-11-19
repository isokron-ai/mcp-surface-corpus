#!/usr/bin/env node
// Vendors the checker engine from a checkout of isokron-ai/mcp-check, or verifies the vendored copy.
//   node scripts/vendor-engine.mjs --from ../mcp-check   # copy and record sha256s
//   node scripts/vendor-engine.mjs --verify              # exit 1 if a file differs from VENDORED.json
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILES = [
  ['engine/core.js', 'engine/core.js'],
  ['engine/vendor/ajv2020.min.js', 'engine/vendor/ajv2020.min.js'],
  ['engine/vendor/AJV-LICENSE.txt', 'engine/vendor/AJV-LICENSE.txt'],
  ['engine/vendor/THIRD-PARTY-LICENSES.txt', 'engine/vendor/THIRD-PARTY-LICENSES.txt'],
  ['engine/repo-source.cjs', 'src/inputs/repo-source.cjs'],
];
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const manifestPath = join(root, 'engine/VENDORED.json');
const args = process.argv.slice(2);
if (args[0] === '--from' && args[1]) {
  const from = args[1];
  for (const [dst, src] of FILES) copyFileSync(join(from, src), join(root, dst));
  const { createRequire } = await import('node:module');
  const M = createRequire(import.meta.url)(join(root, 'engine/core.js'));
  const m = { from: 'isokron-ai/mcp-check', commit: args[3] || null, rubric_version: M.RUBRIC_VERSION, checks: M.CHECKS.length,
    files: FILES.map(([dst, src]) => ({ path: dst, source: src, sha256: sha(join(root, dst)) })) };
  writeFileSync(manifestPath, JSON.stringify(m, null, 2) + '\n');
  console.log(`vendored rubric ${m.rubric_version}, ${m.checks} checks`);
} else if (args[0] === '--verify') {
  const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const bad = m.files.filter((f) => sha(join(root, f.path)) !== f.sha256).map((f) => f.path);
  if (bad.length) { console.error(`engine differs from VENDORED.json: ${bad.join(', ')}`); process.exit(1); }
  console.log(`engine verified (${m.files.length} files, rubric ${m.rubric_version})`);
} else {
  console.error('usage: vendor-engine.mjs --from <mcp-check checkout> [--commit SHA] | --verify');
  process.exit(2);
}
