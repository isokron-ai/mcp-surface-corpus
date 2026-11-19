#!/usr/bin/env node
/**
 * Layers (c) and (d) plus source facts, from the target's source archive, without running anything
 * of it. Runs inside a sandbox container with no network; the archive comes in on stdin (the GitHub
 * tar.gz of the pinned commit) and is read in memory: nothing is unpacked to disk.
 *
 *   node static.mjs [--subdir path/in/repo] < source.tar.gz
 *
 * Prints one JSON object (isokron-surface-static/1).
 */
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readTar } from '../src/tar.mjs';
import { sdkFromFile, primarySdk } from '../src/sdk.mjs';
import { extractGo } from '../src/go-extract.mjs';
import { extractReadme, documentedCommands } from '../src/readme-extract.mjs';
import { envRefsFromSource, envRefsFromReadme } from '../src/env-refs.mjs';

const require = createRequire(import.meta.url);
const RS = require('../engine/repo-source.cjs');

export const FORMAT = 'isokron-surface-static/1';
const MAX_SRC_FILES = 600;
const MAX_SRC_BYTES = 600 * 1024;
const MAX_KEEP = 1536 * 1024;

const LANG = { ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript', js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', py: 'python', go: 'go', rs: 'rust', java: 'java', kt: 'kotlin', cs: 'csharp', rb: 'ruby', php: 'php', swift: 'swift', ex: 'elixir', exs: 'elixir', dart: 'dart', scala: 'scala', cpp: 'cpp', c: 'c', zig: 'zig', lua: 'lua' };
const LOCKS = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|uv\.lock|poetry\.lock|pdm\.lock|Pipfile\.lock|requirements[^/]*\.txt|go\.mod|Cargo\.lock|Cargo\.toml|package\.json|pyproject\.toml|setup\.py|setup\.cfg|pom\.xml|build\.gradle(\.kts)?|[^/]+\.csproj)$/;
const SKIP_DIR = /(^|\/)(node_modules|dist|build|out|\.next|vendor|coverage|__pycache__|\.venv|venv|site-packages|\.git)\//;

export function analyseArchive(buf, { subdir = '' } = {}) {
  const sub = subdir.replace(/^\/+|\/+$/g, '');
  let root = null;
  const rel = (p) => {
    const parts = p.split('/');
    if (root === null) root = parts[0];
    const r = parts.slice(1).join('/');
    return r;
  };
  const inSub = (r) => !sub || r === sub || r.startsWith(`${sub}/`);
  const underSub = (r) => (sub ? r.slice(sub.length + 1) : r);
  const isSrc = (r) => /\.(ts|mts|cts|js|mjs|cjs|py|go)$/.test(r) && !/\.d\.ts$/.test(r) && !/\.min\.js$/.test(r) && !SKIP_DIR.test(r);
  const keep = (p, size) => {
    const r = rel(p);
    if (size > MAX_KEEP) return false;
    if (LOCKS.test(r) && !SKIP_DIR.test(r)) return r.split('/').length <= (sub ? sub.split('/').length + 3 : 3) || inSub(r);
    // The repository's own licence file counts for a server kept in a subfolder of a monorepo.
    if (!r.includes('/') && /^(LICENSE|LICENCE|COPYING)[^/]*$/i.test(r)) return true;
    if (!inSub(r)) return false;
    const u = underSub(r);
    if (/^(readme|README)[^/]*\.(md|markdown|rst|txt)$/i.test(u) || /(^|\/)(server|manifest|tools[^/]*|mcp-tools|tool-list)\.json$/.test(u) || /(^|\/)__toolsnaps__\/[^/]+\.snap$/.test(u)) return true;
    if (/^(LICENSE|LICENCE|COPYING)[^/]*$/i.test(u)) return true;
    return isSrc(r) && size <= MAX_SRC_BYTES;
  };
  const { entries, global } = readTar(buf, { want: keep });
  const out = {
    format: FORMAT,
    archive: { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length, entries: entries.length, commit: /^[0-9a-f]{40}$/.test(global.comment || '') ? global.comment : null, subdir: sub || null, subdir_found: false },
    languages: {}, primary_language: null,
    files: { total: 0, in_subdir: 0, links: 0 },
    manifests: [], sdk: { hits: [], primary: null },
    license_files: [],
    readme: null,
    static: { candidates: [], best: null, go: [], scanned_src: 0, src_total: 0, errors: [] },
    env_refs: { source: [], readme: [] },
    documented_commands: [],
    server_json: [],
  };
  const files = new Map();
  for (const e of entries) {
    const r = rel(e.path);
    if (e.type === 'symlink' || e.type === 'link') out.files.links++;
    if (e.type !== 'file') continue;
    out.files.total++;
    // Kept files outside the subfolder (root lock files, the root licence) are read below too.
    if (e.data && !inSub(r)) files.set(r, e.data.toString('utf8'));
    if (!inSub(r)) continue;
    out.archive.subdir_found = true;
    out.files.in_subdir++;
    const ext = (/\.([A-Za-z0-9]+)$/.exec(r) || [])[1];
    const lang = ext && LANG[ext.toLowerCase()];
    if (lang && !SKIP_DIR.test(r)) {
      const L = (out.languages[lang] ||= { files: 0, bytes: 0 });
      L.files++; L.bytes += e.size;
    }
    if (e.data) files.set(r, e.data.toString('utf8'));
  }
  if (!sub) out.archive.subdir_found = true;
  out.primary_language = Object.entries(out.languages).sort((a, b) => b[1].bytes - a[1].bytes)[0]?.[0] || null;

  // Manifests and SDKs: files under the subdir first (depth 0), then the repo root (monorepo locks).
  for (const [r, text] of files) {
    if (!LOCKS.test(r) || SKIP_DIR.test(r)) continue;
    const depth = inSub(r) ? underSub(r).split('/').length - 1 : 50 + r.split('/').length;
    const hits = sdkFromFile(r, text).map((h) => ({ ...h, path: r, depth }));
    out.manifests.push({ path: r, bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex'), sdk_hits: hits.length });
    out.sdk.hits.push(...hits);
    if (/(^|\/)package\.json$/.test(r) && inSub(r) && underSub(r) === 'package.json') {
      try { const j = JSON.parse(text); out.package_json = { name: j.name ?? null, version: j.version ?? null, license: j.license ?? null, bin: j.bin ?? null, type: j.type ?? null, engines: j.engines ?? null, mcpName: j.mcpName ?? null }; } catch { /* not JSON */ }
    }
    if (/(^|\/)pyproject\.toml$/.test(r) && inSub(r) && underSub(r) === 'pyproject.toml') {
      const n = /^name\s*=\s*"([^"]+)"/m.exec(text); const v = /^version\s*=\s*"([^"]+)"/m.exec(text);
      const scripts = /\[project\.scripts\]([\s\S]*?)(\n\[|$)/.exec(text);
      out.pyproject = { name: n ? n[1] : null, version: v ? v[1] : null, scripts: scripts ? [...scripts[1].matchAll(/^([\w.-]+)\s*=/gm)].map((x) => x[1]) : [] };
    }
  }
  out.sdk.primary = primarySdk(out.sdk.hits);

  // Licence files, README, server.json.
  const rootLicences = [];
  for (const [r, text] of files) {
    if (!inSub(r)) {
      if (sub && !r.includes('/') && /^(LICENSE|LICENCE|COPYING)/i.test(r)) rootLicences.push({ path: r, from: 'root', sha256: createHash('sha256').update(text).digest('hex'), spdx_guess: guessSpdx(text) });
      continue;
    }
    const u = underSub(r);
    if (/^(LICENSE|LICENCE|COPYING)/i.test(u.split('/').pop()) && !u.includes('/')) out.license_files.push({ path: r, from: sub ? 'subdir' : 'root', sha256: createHash('sha256').update(text).digest('hex'), spdx_guess: guessSpdx(text) });
    if (/^readme[^/]*\.(md|markdown|rst|txt)$/i.test(u) && !out.readme) {
      const tools = extractReadme(text);
      out.readme = { path: r, bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex'), tools };
      out.env_refs.readme = [...envRefsFromReadme(text)].sort();
      out.documented_commands = documentedCommands(text);
    }
    if (/(^|\/)server\.json$/.test(u) && !SKIP_DIR.test(r)) {
      try { const j = JSON.parse(text); if (j && typeof j === 'object') out.server_json.push({ path: r, json: j }); } catch { /* not JSON */ }
    }
  }

  if (!out.license_files.length) out.license_files = rootLicences;

  // Layer (c): repo-source (exact lists, MCPB manifests, JS/TS/Python registrations) and Go.
  const paths = [...files.keys()].filter(inSub);
  const plan = RS.planFiles(paths);
  out.static.src_total = plan.src.length;
  const cands = [];
  const snaps = []; const seenSnap = new Set();
  for (const p of plan.exact) {
    const t = files.get(p); if (!t) continue;
    let ts = null; try { ts = RS.toolsFromJson(t); } catch { ts = null; }
    if (!ts || !ts.length) continue;
    if (/__toolsnaps__/.test(p)) { ts.forEach((x) => { if (!seenSnap.has(x.name)) { seenSnap.add(x.name); snaps.push(x); } }); } else cands.push({ kind: 'committed', fidelity: 'exact', path: p, tools: ts });
  }
  if (snaps.length) cands.push({ kind: 'snapshots', fidelity: 'exact', path: null, tools: snaps });
  for (const p of plan.manifests) {
    const t = files.get(p); if (!t) continue;
    let m = null; try { m = RS.fromMcpbManifest(t); } catch { m = null; }
    if (m && m.tools && m.tools.length) cands.push({ kind: 'mcpb', fidelity: m.fidelity, path: p, tools: m.tools });
  }
  // JavaScript, TypeScript and Python: the shared reader, which detects the SDK and schema library from the
  // manifests, reads the registrations as that SDK lists them, and sets aside tools that are not registered at run time.
  const srcPaths = plan.src.filter((x) => !SKIP_DIR.test(x));
  let an = { found: [], tools: [], excluded: [], sdk: null, files: 0 };
  try { an = RS.analyseRepo(files, { maxSourceFiles: MAX_SRC_FILES }); } catch (e) { out.static.errors.push({ path: null, error: String(e.message).slice(0, 200) }); }
  const found = an.tools;
  const goFound = []; const goNames = new Set();
  let scanned = an.files;
  for (const p of srcPaths) { const t = files.get(p); if (t) for (const n of envRefsFromSource(t)) out.env_refs.source.push(n); }
  for (const p of paths.filter((x) => /\.go$/.test(x) && !SKIP_DIR.test(x) && !/_test\.go$/.test(x))) {
    if (scanned >= MAX_SRC_FILES) break;
    const t = files.get(p); if (!t) continue;
    scanned++;
    let ts = [];
    try { ts = extractGo(t); } catch (e) { out.static.errors.push({ path: p, error: String(e.message).slice(0, 200) }); }
    for (const x of ts) {
      if (!x || !x.tool || typeof x.tool.name !== 'string' || goNames.has(x.tool.name)) continue;
      goNames.add(x.tool.name);
      goFound.push({ path: p, ...x });
    }
    for (const n of envRefsFromSource(t)) out.env_refs.source.push(n);
  }
  out.static.scanned_src = scanned;
  out.static.sdk_read = an.sdk ? { kind: an.sdk.kind ?? null, version: an.sdk.version ?? null, zod: an.sdk.zod ?? null, py: an.sdk.py ?? null } : null;
  out.env_refs.source = [...new Set(out.env_refs.source)].sort();
  const left = an.excluded.map((x) => ({ reasons: [...new Set(x.marks.filter((m) => m.exclude).map((m) => m.reason))] }));
  const kept = an.tools.filter((x) => x.marks && x.marks.length).length;
  out.static.left_out = { tools: left.length, reasons: [...new Set(left.flatMap((x) => x.reasons))].sort() };
  out.static.kept_marked = kept;
  for (const [list, kind] of [[found, 'source'], [goFound, 'source-go']]) {
    if (!list.length) continue;
    const allLiteral = list.every((x) => x.fidelity === 'literal');
    cands.push({ kind, fidelity: allLiteral ? 'literal' : 'derived', path: null, tools: list.map((x) => x.tool), where: list.map((x) => ({ name: x.tool.name, path: x.path, line: x.line, fidelity: x.fidelity })) });
  }
  const rank = { exact: 0, literal: 1, derived: 2, names: 3 };
  cands.sort((a, b) => rank[a.fidelity] - rank[b.fidelity] || b.tools.length - a.tools.length);
  out.static.candidates = cands;
  out.static.best = cands[0] ? { kind: cands[0].kind, fidelity: cands[0].fidelity, tools: cands[0].tools.length } : null;
  return out;
}

function guessSpdx(t) {
  const s = t.slice(0, 3000);
  if (/MIT License|Permission is hereby granted, free of charge/i.test(s)) return 'MIT';
  if (/Apache License,?\s+Version 2\.0/i.test(s)) return 'Apache-2.0';
  if (/GNU AFFERO GENERAL PUBLIC LICENSE/i.test(s)) return 'AGPL-3.0';
  if (/GNU LESSER GENERAL PUBLIC LICENSE/i.test(s)) return 'LGPL';
  if (/GNU GENERAL PUBLIC LICENSE/i.test(s)) return /Version 2/i.test(s) ? 'GPL-2.0' : 'GPL-3.0';
  if (/Mozilla Public License,? (Version|v\.?) ?2\.0/i.test(s)) return 'MPL-2.0';
  if (/Redistribution and use in source and binary forms/i.test(s)) return /Neither the name/i.test(s) ? 'BSD-3-Clause' : 'BSD-2-Clause';
  if (/ISC License|Permission to use, copy, modify, and\/or distribute/i.test(s)) return 'ISC';
  if (/This is free and unencumbered software released into the public domain/i.test(s)) return 'Unlicense';
  if (/Business Source License/i.test(s)) return 'BUSL-1.1';
  return null;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const i = args.indexOf('--subdir');
  const subdir = i >= 0 ? args[i + 1] || '' : '';
  const chunks = []; let n = 0;
  for await (const c of process.stdin) { n += c.length; if (n > 256 * 1024 * 1024) { process.stderr.write('archive over 256 MiB\n'); process.exit(1); } chunks.push(c); }
  let out;
  try { out = analyseArchive(Buffer.concat(chunks), { subdir }); } catch (e) { out = { format: FORMAT, error: String(e.message).slice(0, 500) }; }
  process.stdout.write(`${JSON.stringify(out)}\n`, () => process.exit(out.error ? 1 : 0));
}
