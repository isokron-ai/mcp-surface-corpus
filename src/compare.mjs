// Comparisons: static vs live tool lists (same run), and a target's list now vs its previous run.
import { createHash } from 'node:crypto';

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
export function canonical(x) {
  if (Array.isArray(x)) return `[${x.map(canonical).join(',')}]`;
  if (isObj(x)) return `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canonical(x[k])}`).join(',')}}`;
  return JSON.stringify(x === undefined ? null : x);
}
export const sha = (s) => createHash('sha256').update(s).digest('hex');
export const hashOf = (x) => (x === undefined ? null : sha(canonical(x)));

/** Per-tool fingerprints: the whole definition and each part, so a diff can say what changed. */
export function fingerprint(tools) {
  return (tools || []).filter((t) => isObj(t) && typeof t.name === 'string').map((t) => ({
    name: t.name,
    sha256: hashOf(t),
    parts: { description: hashOf(t.description), title: hashOf(t.title), inputSchema: hashOf(t.inputSchema), outputSchema: hashOf(t.outputSchema), annotations: hashOf(t.annotations), _meta: hashOf(t._meta) },
    params: isObj(t.inputSchema) && isObj(t.inputSchema.properties) ? Object.keys(t.inputSchema.properties).sort() : [],
  }));
}

/** Static vs live for one target. Names only in one list, and for shared tools which parts agree. */
export function staticVsLive(staticTools, liveTools) {
  const S = new Map(fingerprint(staticTools).map((t) => [t.name, t]));
  const L = new Map(fingerprint(liveTools).map((t) => [t.name, t]));
  const both = [...L.keys()].filter((n) => S.has(n));
  const onlyLive = [...L.keys()].filter((n) => !S.has(n));
  const onlyStatic = [...S.keys()].filter((n) => !L.has(n));
  const union = new Set([...S.keys(), ...L.keys()]).size;
  const agree = { description: 0, inputSchema: 0, params: 0, annotations: 0, whole: 0 };
  const paramJ = [];
  for (const n of both) {
    const a = S.get(n); const b = L.get(n);
    if (a.parts.description === b.parts.description) agree.description++;
    if (a.parts.inputSchema === b.parts.inputSchema) agree.inputSchema++;
    if (a.parts.annotations === b.parts.annotations) agree.annotations++;
    if (a.sha256 === b.sha256) agree.whole++;
    const pa = new Set(a.params); const pb = new Set(b.params);
    const inter = [...pa].filter((x) => pb.has(x)).length;
    const uni = new Set([...pa, ...pb]).size;
    paramJ.push(uni ? inter / uni : 1);
    if (uni && inter === uni) agree.params++;
  }
  return { static_tools: S.size, live_tools: L.size, shared: both.length, only_live: onlyLive, only_static: onlyStatic, name_jaccard: union ? both.length / union : 1, agree, param_jaccard_mean: paramJ.length ? paramJ.reduce((x, y) => x + y, 0) / paramJ.length : null };
}

/** Run-over-run diff from two fingerprint lists (records keep fingerprints, so no raw data is needed). */
export function diffRuns(prevFp, curFp) {
  const P = new Map((prevFp || []).map((t) => [t.name, t]));
  const C = new Map((curFp || []).map((t) => [t.name, t]));
  const added = [...C.keys()].filter((n) => !P.has(n));
  const removed = [...P.keys()].filter((n) => !C.has(n));
  const changed = [];
  for (const [n, c] of C) {
    const p = P.get(n);
    if (!p || p.sha256 === c.sha256) continue;
    changed.push({ name: n, parts: Object.keys(c.parts).filter((k) => c.parts[k] !== p.parts[k]) });
  }
  return { added, removed, changed, unchanged: [...C.keys()].filter((n) => P.has(n) && P.get(n).sha256 === C.get(n).sha256).length, any: added.length + removed.length + changed.length > 0 };
}
