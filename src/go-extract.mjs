// Static tool extraction for Go MCP servers (no execution): mark3labs/mcp-go `mcp.NewTool(...)` and
// the official go-sdk `&mcp.Tool{Name: ..., Description: ...}`. Fidelity "derived": parameter types
// come from the With* option names; schemas from Go structs are not derived.

function goString(src, i) {
  // Returns [value, end] for a Go string literal (or "a" + "b" concatenation of literals) at i.
  let val = '';
  let j = i;
  for (;;) {
    while (/\s/.test(src[j] || '')) j++;
    if (src[j] === '"') {
      let k = j + 1;
      while (k < src.length && src[k] !== '"') { if (src[k] === '\\') { const e = src[k + 1]; val += e === 'n' ? '\n' : e === 't' ? '\t' : e; k += 2; continue; } if (src[k] === '\n') return null; val += src[k++]; }
      j = k + 1;
    } else if (src[j] === '`') {
      const k = src.indexOf('`', j + 1);
      if (k < 0) return null;
      val += src.slice(j + 1, k);
      j = k + 1;
    } else return null;
    let k = j;
    while (/\s/.test(src[k] || '')) k++;
    if (src[k] === '+') { j = k + 1; continue; }
    return [val, j];
  }
}

function argsOf(src, open) {
  // Top-level comma-separated arguments of the call whose '(' is at `open`. Returns [args, end].
  const args = [];
  let depth = 0; let start = open + 1; let i = open;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === '"') { i++; while (i < src.length && src[i] !== '"') { if (src[i] === '\\') i++; i++; } continue; }
    if (c === '`') { i = src.indexOf('`', i + 1); if (i < 0) return [args, src.length]; continue; }
    if (c === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) break; continue; }
    if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') { depth--; if (depth === 0) { args.push(src.slice(start, i)); return [args, i]; } }
    else if (c === ',' && depth === 1) { args.push(src.slice(start, i)); start = i + 1; }
  }
  return [args, i];
}

const TYPE = { WithString: 'string', WithNumber: 'number', WithInteger: 'integer', WithBoolean: 'boolean', WithArray: 'array', WithObject: 'object', WithAny: null };
const ANN = { WithReadOnlyHintAnnotation: 'readOnlyHint', WithDestructiveHintAnnotation: 'destructiveHint', WithIdempotentHintAnnotation: 'idempotentHint', WithOpenWorldHintAnnotation: 'openWorldHint' };

function parseParam(arg) {
  const m = /^\s*(?:mcp\.)?(With(?:String|Number|Integer|Boolean|Array|Object|Any))\s*\(/.exec(arg);
  if (!m) return null;
  const nameLit = goString(arg, m[0].length);
  if (!nameLit) return null;
  const schema = {};
  if (TYPE[m[1]]) schema.type = TYPE[m[1]];
  const d = /(?:mcp\.)?Description\s*\(/.exec(arg);
  if (d) { const s = goString(arg, d.index + d[0].length); if (s) schema.description = s[0]; }
  const en = /(?:mcp\.)?Enum\s*\(([^)]*)\)/.exec(arg);
  if (en) { const vals = [...en[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]); if (vals.length) schema.enum = vals; }
  const def = /(?:mcp\.)?Default(?:String|Number|Bool)\s*\(\s*([^)]*)\)/.exec(arg);
  if (def) { const v = def[1].trim(); schema.default = /^".*"$/.test(v) ? v.slice(1, -1) : v === 'true' ? true : v === 'false' ? false : Number.isFinite(Number(v)) ? Number(v) : v; }
  return { name: nameLit[0], schema, required: /(?:mcp\.)?Required\s*\(\s*\)/.test(arg) };
}

export function extractGo(src) {
  const out = [];
  const re = /\bmcp\.NewTool\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    const open = m.index + m[0].length - 1;
    const [args, end] = argsOf(src, open);
    if (!args.length) continue;
    const nm = goString(args[0], 0);
    if (!nm) continue;
    const tool = { name: nm[0], inputSchema: { type: 'object', properties: {} } };
    const required = [];
    const annotations = {};
    for (const a of args.slice(1)) {
      const dm = /^\s*(?:mcp\.)?WithDescription\s*\(/.exec(a);
      if (dm) { const s = goString(a, dm[0].length); if (s) tool.description = s[0]; continue; }
      const tm = /^\s*(?:mcp\.)?WithTitleAnnotation\s*\(/.exec(a);
      if (tm) { const s = goString(a, tm[0].length); if (s) annotations.title = s[0]; continue; }
      const am = /^\s*(?:mcp\.)?(With\w+HintAnnotation)\s*\(\s*(true|false)\s*\)/.exec(a);
      if (am && ANN[am[1]]) { annotations[ANN[am[1]]] = am[2] === 'true'; continue; }
      const p = parseParam(a);
      if (p) { tool.inputSchema.properties[p.name] = p.schema; if (p.required) required.push(p.name); }
    }
    if (required.length) tool.inputSchema.required = required;
    if (Object.keys(annotations).length) tool.annotations = annotations;
    out.push({ tool, fidelity: 'derived', line: src.slice(0, m.index).split('\n').length });
    re.lastIndex = end;
  }
  const re2 = /&mcp\.Tool\s*\{/g;
  while ((m = re2.exec(src))) {
    const body = src.slice(m.index, m.index + 4000);
    const n = /\bName\s*:\s*/.exec(body);
    if (!n) continue;
    const nm = goString(body, n.index + n[0].length);
    if (!nm) continue;
    const tool = { name: nm[0], inputSchema: { type: 'object' } };
    const d = /\bDescription\s*:\s*/.exec(body);
    if (d) { const s = goString(body, d.index + d[0].length); if (s) tool.description = s[0]; }
    out.push({ tool, fidelity: 'derived', line: src.slice(0, m.index).split('\n').length, schema_unknown: true });
  }
  return out;
}
