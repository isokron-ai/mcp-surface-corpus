#!/usr/bin/env node
/**
 * Runs the checker engine (engine/core.js, the same file as isokron.ai/mcp-check) over every tool
 * list acquired for one target, and derives the features, token estimates, fingerprints and the
 * static-vs-live comparison. Data in, data out: runs in a container with no network.
 *
 *   node analyse.mjs < input.json > analysis.json
 *
 * input:  { live_pages: [JSON-RPC answers] | null, static: [{ kind, fidelity, tools }], readme: [tools] | null,
 *           registry: [tools] | null, probe: <probe output, for list features> | null }
 * output: isokron-surface-analysis/1
 */
import { createRequire } from 'node:module';
import { toolFeatures, listFeatures } from '../src/features.mjs';
import { estimate } from '../src/tokens.mjs';
import { fingerprint, staticVsLive, sha } from '../src/compare.mjs';

const require = createRequire(import.meta.url);
const M = require('../engine/core.js');

export const FORMAT = 'isokron-surface-analysis/1';

/** One engine run, kept whole (every check, every finding with its evidence), plus a compact matrix. */
const SEV_RANK = { advice: 0, attention: 1, blocking: 2 };
export function runEngine(input) {
  const text = typeof input === 'string' ? input : JSON.stringify(input);
  const t0 = Date.now();
  const parsed = M.parseInput(text);
  if (parsed.error) return { ok: false, error: parsed.error, error_type: parsed.errorType || null, ms: Date.now() - t0 };
  let r;
  try { r = M.analyse(parsed); } catch (e) { return { ok: false, error: `engine threw: ${String(e.message).slice(0, 300)}`, error_type: 'engine_exception', ms: Date.now() - t0 }; }
  const findings = M.allFindings(r);
  const matrix = {};
  for (const c of M.CHECKS) matrix[c.id] = { findings: 0, tools: 0, sev: null };
  const toolsHit = {};
  for (const f of findings) {
    const m = (matrix[f.id] ||= { findings: 0, tools: 0 });
    m.findings++;
    // The severity a finding carries, not the check's default: an envelope check is advice for a server of the earlier era.
    if (!m.sev || (SEV_RANK[f.severity] ?? -1) > (SEV_RANK[m.sev] ?? -1)) m.sev = f.severity;
    if (f.tool) (toolsHit[f.id] ||= new Set()).add(f.tool);
  }
  for (const [id, s] of Object.entries(toolsHit)) matrix[id].tools = s.size;
  const grades = {};
  for (const [k, s] of Object.entries(r.sections)) grades[k] = { grade: s.grade ?? null, score: s.score ?? null, ready: s.ready ?? null, counts: s.counts ?? null, caps: s.caps ?? [] };
  return { ok: true, ms: Date.now() - t0, report: r, matrix, grades, tool_count: r.input.tools, skipped: r.input.skipped, era: r.input.era, catalog_hash: r.input.catalogHash, validator: r.validator };
}

export function analyse(input) {
  const out = {
    format: FORMAT,
    engine: { rubric_version: M.RUBRIC_VERSION, spec_version: M.SPEC_VERSION, report_schema: M.REPORT_SCHEMA, sources_read: M.SOURCES_READ, checks: M.CHECKS.length, check_ids: M.CHECKS.map((c) => ({ id: c.id, section: c.section, severity: c.severity })) },
    runs: {}, features: {}, tokens: {}, fingerprints: {}, static_vs_live: null, list_features: null,
  };
  const liveTools = [];
  if (Array.isArray(input.live_pages) && input.live_pages.length) {
    for (const p of input.live_pages) if (p && p.result && Array.isArray(p.result.tools)) liveTools.push(...p.result.tools);
    out.runs.live = runEngine(input.live_pages);
    out.features.live = toolFeatures(liveTools);
    // The bytes a client pays for: every page's result as the server sent it, re-serialised compactly.
    const resultText = JSON.stringify(input.live_pages.length === 1 ? input.live_pages[0].result : input.live_pages.map((p) => p.result));
    out.tokens.live = { ...estimate(resultText), tools_only: estimate(JSON.stringify(liveTools)), per_tool: liveTools.slice(0, 2000).map((t) => ({ name: typeof t.name === 'string' ? t.name.slice(0, 128) : null, ...estimate(JSON.stringify(t)) })) };
    out.fingerprints.live = fingerprint(liveTools);
  }
  if (input.probe) out.list_features = listFeatures(input.probe);
  const statics = Array.isArray(input.static) ? input.static : [];
  statics.forEach((c, i) => {
    const key = i === 0 ? 'static_best' : `static_${i}_${c.kind}`;
    out.runs[key] = { ...runEngine({ tools: c.tools }), kind: c.kind, fidelity: c.fidelity };
    out.features[key] = toolFeatures(c.tools);
    out.fingerprints[key] = fingerprint(c.tools);
    if (i === 0) out.tokens.static_best = estimate(JSON.stringify({ tools: c.tools }));
  });
  if (Array.isArray(input.readme) && input.readme.length) {
    out.runs.readme = { ...runEngine({ tools: input.readme }), fidelity: 'names' };
    out.fingerprints.readme = fingerprint(input.readme);
  }
  if (Array.isArray(input.registry) && input.registry.length) {
    out.runs.registry = runEngine({ tools: input.registry });
    out.fingerprints.registry = fingerprint(input.registry);
  }
  if (liveTools.length && statics.length) {
    out.static_vs_live = { best: { kind: statics[0].kind, fidelity: statics[0].fidelity, ...staticVsLive(statics[0].tools, liveTools) } };
    const a = out.runs.live; const b = out.runs.static_best;
    if (a.ok && b.ok) {
      const d = {};
      for (const id of Object.keys(a.matrix)) {
        const l = a.matrix[id].findings > 0; const s = (b.matrix[id] || { findings: 0 }).findings > 0;
        d[id] = l && s ? 'both' : l ? 'live_only' : s ? 'static_only' : 'neither';
      }
      out.static_vs_live.checks = d;
    }
    if (out.runs.readme && out.runs.readme.ok) out.static_vs_live.readme = staticVsLive(input.readme, liveTools);
  }
  out.input_sha256 = sha(JSON.stringify(input));
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  let out;
  try { out = analyse(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { out = { format: FORMAT, error: String(e.message).slice(0, 500) }; }
  process.stdout.write(`${JSON.stringify(out)}\n`, () => process.exit(out.error ? 1 : 0));
}
