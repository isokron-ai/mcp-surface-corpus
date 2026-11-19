// repo-source: find an MCP server's tool list from its source, without running it. Browser and Node.
// Every download is size-capped (MAX_FILE per file, MAX_JSON per API answer); nothing fetched is executed.
//
//   await RepoSource.fromGitHub('github.com/owner/repo', { fetch })   -> { candidates, best, hints }
//   await RepoSource.fromRegistry('io.github.owner/name', { fetch })  -> server.json summary (remotes, packages, repo)
//   RepoSource.extractFromFile(path, text)                            -> tools found statically in one file
//
// Nothing is executed. Sources, best first:
//   exact    a committed tool list (tools.json, __toolsnaps__/*.snap), or an MCPB manifest.json with
//            _meta[*].static_responses["tools/list"]
//   literal  JS/TS object literals { name, description, inputSchema: {JSON Schema literal} }
//   derived  SDK registrations converted the way the SDK would: TS registerTool / server.tool with zod shapes,
//            Python @mcp.tool functions (type hints and docstrings). Schemas are close to, not exactly, what
//            the server sends; the report must say so.
//   names    an MCPB manifest "tools" array (name and description only)
// Network: GitHub's REST API (CORS for any origin, 60 requests/hour per user IP without a token) for the file tree,
// raw.githubusercontent.com for files; data.jsdelivr.com / cdn.jsdelivr.net as the fallback. The registry API at
// registry.modelcontextprotocol.io sends Access-Control-Allow-Origin: *. Nothing goes to IsoKron.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RepoSource = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ------------------------------------------------------------ tokenizer (JS/TS)
  const PUNCT_BEFORE_REGEX = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^', '=>', '&&', '||', '??', 'return', 'typeof', 'case']);
  function tokenize(src) {
    const t = []; let i = 0; const n = src.length;
    const push = (type, value, start) => t.push({ type, value, start });
    while (i < n) {
      const c = src[i];
      if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
      if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
      if (/\s/.test(c)) { i++; continue; }
      const s = i;
      if (c === '"' || c === "'") {
        let v = ''; i++;
        while (i < n && src[i] !== c) {
          if (src[i] === '\\') { const e = src[i + 1]; v += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e === 'u' ? String.fromCharCode(parseInt(src.substr(i + 2, 4), 16)) : e; i += e === 'u' ? 6 : 2; continue; }
          if (src[i] === '\n') break;
          v += src[i++];
        }
        i++; push('str', v, s); continue;
      }
      if (c === '`') {
        let v = ''; let dyn = false; i++;
        while (i < n && src[i] !== '`') {
          if (src[i] === '\\') { v += src[i + 1] === 'n' ? '\n' : src[i + 1]; i += 2; continue; }
          if (src[i] === '$' && src[i + 1] === '{') { dyn = true; let d = 1; i += 2; while (i < n && d) { if (src[i] === '{') d++; else if (src[i] === '}') d--; i++; } continue; }
          v += src[i++];
        }
        i++; push(dyn ? 'tpl' : 'str', v, s); continue;
      }
      if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(src[i + 1]))) { const m = /^(0[xX][0-9a-fA-F_]+|[0-9_]*\.?[0-9_]+(?:[eE][+-]?[0-9]+)?)/.exec(src.slice(i, i + 40)); i += m ? m[0].length : 1; push('num', Number((m ? m[0] : c).replace(/_/g, '')), s); continue; }
      if (/[A-Za-z_$@#]/.test(c)) { const m = /^[A-Za-z_$@#][\w$]*/.exec(src.slice(i, i + 200)); i += m[0].length; push('id', m[0], s); continue; }
      if (c === '/') {
        const prev = t[t.length - 1];
        if (!prev || (prev.type === 'p' && PUNCT_BEFORE_REGEX.has(prev.value)) || (prev.type === 'id' && PUNCT_BEFORE_REGEX.has(prev.value))) {
          i++; let cls = false;
          while (i < n && (src[i] !== '/' || cls) && src[i] !== '\n') { if (src[i] === '\\') i++; else if (src[i] === '[') cls = true; else if (src[i] === ']') cls = false; i++; }
          i++; while (/[a-z]/.test(src[i] || '')) i++;
          push('regex', src.slice(s, i), s); continue;
        }
      }
      const three = src.substr(i, 3); const two = src.substr(i, 2);
      if (['...', '===', '!==', '??='].includes(three)) { i += 3; push('p', three, s); continue; }
      if (['=>', '&&', '||', '??', '==', '!=', '<=', '>=', '?.', '++', '--'].includes(two)) { i += 2; push('p', two, s); continue; }
      i++; push('p', c, s);
    }
    return t;
  }

  // ------------------------------------------------------------ literal parser with skipping
  // parseValue returns { value, end, exact }. Non-literal values become SKIP (exact=false) and are left out of objects.
  const SKIP = { skip: true };
  function skipExpr(t, i) {
    let d = 0;
    for (; i < t.length; i++) {
      const v = t[i].type === 'p' ? t[i].value : null;
      if (v === '(' || v === '[' || v === '{') d++;
      else if (v === ')' || v === ']' || v === '}') { if (d === 0) return i; d--; }
      else if ((v === ',' || v === ';') && d === 0) return i;
    }
    return i;
  }
  function isP(tok, v) { return tok && tok.type === 'p' && tok.value === v; }
  function parseValue(t, i, ctx) {
    const tok = t[i];
    if (!tok) return { value: SKIP, end: i, exact: false };
    let r = null;
    if (tok.type === 'str') {
      // 'a' + 'b' concatenation of plain strings
      let v = tok.value; let j = i + 1;
      while (isP(t[j], '+') && t[j + 1] && t[j + 1].type === 'str') { v += t[j + 1].value; j += 2; }
      r = { value: v, end: j, exact: true };
    } else if (tok.type === 'num') r = { value: tok.value, end: i + 1, exact: true };
    else if (isP(tok, '-') && t[i + 1] && t[i + 1].type === 'num') r = { value: -t[i + 1].value, end: i + 2, exact: true };
    else if (tok.type === 'id' && (tok.value === 'true' || tok.value === 'false')) r = { value: tok.value === 'true', end: i + 1, exact: true };
    else if (tok.type === 'id' && tok.value === 'null') r = { value: null, end: i + 1, exact: true };
    else if (isP(tok, '{')) r = parseObject(t, i, ctx);
    else if (isP(tok, '[')) r = parseArray(t, i, ctx);
    else if (tok.type === 'id' && ctx && ctx.zod && ctx.zodNames.has(tok.value) && isP(t[i + 1], '.')) {
      const z = parseZod(t, i, ctx);
      if (z) r = z;
    } else if (tok.type === 'id' && ctx && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, tok.value) && !isP(t[i + 1], '.') && !isP(t[i + 1], '(')) {
      r = { value: ctx.consts[tok.value].value, end: i + 1, exact: ctx.consts[tok.value].exact };
    }
    if (r) {
      // TS: `as const`, `satisfies X`, non-null `!`
      let j = r.end;
      while (t[j] && t[j].type === 'id' && (t[j].value === 'as' || t[j].value === 'satisfies')) j = skipType(t, j + 1);
      if (isP(t[j], '!')) j++;
      const nx = t[j];
      if (!nx || isP(nx, ',') || isP(nx, '}') || isP(nx, ']') || isP(nx, ')') || isP(nx, ';')) return Object.assign(r, { end: j });
    }
    return { value: SKIP, end: skipExpr(t, i), exact: false };
  }
  function skipType(t, j) { // skip a TS type after `as`: identifiers, dots, generics
    let d = 0;
    for (; j < t.length; j++) {
      const v = t[j].type === 'p' ? t[j].value : null;
      if (v === '<' || v === '(' || v === '[' || v === '{') d++;
      else if (v === '>' || v === ')' || v === ']' || v === '}') { if (d === 0) return j; d--; }
      else if ((v === ',' || v === ';') && d === 0) return j;
    }
    return j;
  }
  const HANDLER_KEYS = new Set(['handler', 'execute', 'callback', 'run', 'cb', 'fn', 'impl']);
  function parseObject(t, i, ctx) {
    const o = {}; let exact = true; const optionalKeys = new Set(); i++;
    while (i < t.length && !isP(t[i], '}')) {
      const k = t[i];
      if (isP(k, '...')) { exact = false; i = skipExpr(t, i + 1); if (isP(t[i], ',')) i++; continue; }
      let key = null;
      if (k.type === 'str' || k.type === 'id') key = String(k.value);
      else if (k.type === 'num') key = String(k.value);
      else if (isP(k, '[')) { exact = false; i = skipExpr(t, i); if (isP(t[i], ',')) i++; continue; }
      if (key === null) return { value: SKIP, end: skipExpr(t, i), exact: false };
      // method shorthand: name(...) { } / async name() {} / get x() {}
      if (isP(t[i + 1], '(') || (k.type === 'id' && (key === 'async' || key === 'get' || key === 'set') && t[i + 1] && t[i + 1].type === 'id')) {
        let j = i + 1; while (t[j] && !isP(t[j], '{')) j++;
        j = matchClose(t, j) + 1; exact = false; i = isP(t[j], ',') ? j + 1 : j; continue;
      }
      if (isP(t[i + 1], ',') || isP(t[i + 1], '}')) { // shorthand { name }
        if (ctx && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, key)) { o[key] = ctx.consts[key].value; exact = exact && ctx.consts[key].exact; } else exact = false;
        i += isP(t[i + 1], ',') ? 2 : 1; continue;
      }
      let j = i + 1;
      if (isP(t[j], '?')) j++;
      if (!isP(t[j], ':')) return { value: SKIP, end: skipExpr(t, i), exact: false };
      const v = parseValue(t, j + 1, ctx);
      if (v.optional) optionalKeys.add(key);
      if (v.value !== SKIP) { o[key] = v.value; exact = exact && v.exact !== false; } else if (!HANDLER_KEYS.has(key)) exact = false;
      i = v.end;
      if (isP(t[i], ',')) i++;
      else if (!isP(t[i], '}')) return { value: SKIP, end: skipExpr(t, i), exact: false };
    }
    return { value: o, end: i + 1, exact, optionalKeys };
  }
  function parseArray(t, i, ctx) {
    const a = []; let exact = true; i++;
    while (i < t.length && !isP(t[i], ']')) {
      if (isP(t[i], '...')) { exact = false; i = skipExpr(t, i + 1); if (isP(t[i], ',')) i++; continue; }
      const v = parseValue(t, i, ctx);
      if (v.value !== SKIP) a.push(v.value); else exact = false;
      exact = exact && v.exact !== false;
      i = v.end;
      if (isP(t[i], ',')) i++;
      else if (!isP(t[i], ']')) return { value: SKIP, end: skipExpr(t, i), exact: false };
    }
    return { value: a, end: i + 1, exact };
  }
  function matchClose(t, i) {
    const open = t[i] && t[i].value; const close = open === '{' ? '}' : open === '(' ? ')' : ']'; let d = 0;
    for (; i < t.length; i++) { if (isP(t[i], open)) d++; else if (isP(t[i], close)) { d--; if (d === 0) return i; } }
    return t.length - 1;
  }

  // ------------------------------------------------------------ zod -> JSON Schema (the common subset)
  // z.string().min(1).describe('x').optional() and friends. Unknown parts make the result inexact, not wrong.
  function parseZod(t, i, ctx) {
    // collect chain: z . name ( args ) . name ( args ) ...
    let j = i + 1; const calls = [];
    while (isP(t[j], '.') && t[j + 1] && t[j + 1].type === 'id') {
      const name = t[j + 1].value; j += 2;
      let args = [];
      if (isP(t[j], '(')) {
        const close = matchClose(t, j); let k = j + 1;
        while (k < close) { const v = parseValue(t, k, ctx); args.push(v); k = v.end; if (isP(t[k], ',')) k++; else break; }
        j = close + 1;
      }
      calls.push({ name, args });
    }
    if (!calls.length) return null;
    const out = zodToSchema(calls, ctx);
    return { value: out.schema, end: j, exact: out.exact, zod: true, optional: out.optional };
  }
  function zodToSchema(calls, ctx) {
    let s = {}; let exact = true; let optional = false;
    const base = calls[0]; const argv = (k) => (base.args[k] ? base.args[k].value : undefined);
    switch (base.name) {
      case 'string': s = { type: 'string' }; break;
      case 'number': s = { type: 'number' }; break;
      case 'int': case 'bigint': s = { type: 'integer' }; break;
      case 'boolean': s = { type: 'boolean' }; break;
      case 'null': s = { type: 'null' }; break;
      case 'any': case 'unknown': s = {}; break;
      case 'literal': s = { const: argv(0) }; break;
      case 'enum': s = Array.isArray(argv(0)) ? { type: 'string', enum: argv(0) } : (exact = false, { type: 'string' }); break;
      case 'nativeEnum': s = {}; exact = false; break;
      case 'array': { const it = argv(0); s = { type: 'array', items: it && it !== SKIP ? it : {} }; if (!it || it === SKIP || base.args[0].exact === false) exact = false; break; }
      case 'object': case 'strictObject': case 'looseObject': { const sh = argv(0); const r = shapeToSchema(sh && sh !== SKIP ? sh : {}, base.args[0] ? base.args[0].optionalKeys : null); s = r.schema; if (!sh || sh === SKIP || base.args[0].exact === false) exact = false; break; }
      case 'record': { const v = base.args.length > 1 ? argv(1) : argv(0); s = { type: 'object', additionalProperties: v && v !== SKIP ? v : {} }; break; }
      case 'union': { const a = argv(0); s = Array.isArray(a) ? { anyOf: a } : {}; if (!Array.isArray(a)) exact = false; break; }
      case 'url': s = { type: 'string', format: 'uri' }; break;
      case 'email': s = { type: 'string', format: 'email' }; break;
      case 'uuid': s = { type: 'string', format: 'uuid' }; break;
      default: exact = false;
    }
    for (const c of calls.slice(1)) {
      const a0 = c.args[0] ? c.args[0].value : undefined;
      switch (c.name) {
        case 'describe': if (typeof a0 === 'string') s.description = a0; else exact = false; break;
        case 'optional': case 'nullish': optional = true; break;
        case 'nullable': s = s.type ? Object.assign({}, s, { type: [].concat(s.type, 'null') }) : s; break;
        case 'default': optional = true; if (a0 !== SKIP && a0 !== undefined) s.default = a0; break;
        case 'int': s.type = 'integer'; break;
        case 'min': if (typeof a0 === 'number') s[s.type === 'string' ? 'minLength' : s.type === 'array' ? 'minItems' : 'minimum'] = a0; break;
        case 'max': if (typeof a0 === 'number') s[s.type === 'string' ? 'maxLength' : s.type === 'array' ? 'maxItems' : 'maximum'] = a0; break;
        case 'length': if (typeof a0 === 'number') { s.minLength = a0; s.maxLength = a0; } break;
        case 'positive': s.exclusiveMinimum = 0; break;
        case 'nonnegative': s.minimum = 0; break;
        case 'url': s.format = 'uri'; break;
        case 'email': s.format = 'email'; break;
        case 'uuid': s.format = 'uuid'; break;
        case 'datetime': s.format = 'date-time'; break;
        case 'regex': exact = false; break;
        case 'array': s = { type: 'array', items: s }; break;
        case 'strict': s.additionalProperties = false; break;
        case 'passthrough': case 'catchall': delete s.additionalProperties; break;
        case 'meta': if (a0 && typeof a0 === 'object' && typeof a0.description === 'string') s.description = a0.description; break;
        case 'trim': case 'toLowerCase': case 'toUpperCase': case 'finite': case 'safe': case 'nonempty': if (c.name === 'nonempty') s[s.type === 'array' ? 'minItems' : 'minLength'] = 1; break;
        default: exact = false;
      }
    }
    return { schema: s, exact, optional };
  }
  // A zod raw shape { a: z.string(), b: z.number().optional() } -> object schema the way the TS SDK emits it.
  function shapeToSchema(shape, optionalKeys) {
    const props = {}; const required = [];
    Object.keys(shape || {}).forEach((k) => {
      const v = shape[k];
      props[k] = v; if (!(optionalKeys && optionalKeys.has(k))) required.push(k);
    });
    const s = { type: 'object', properties: props };
    if (required.length) s.required = required;
    s.additionalProperties = false;
    return { schema: s };
  }

  // ------------------------------------------------------------ JS/TS extraction
  function zodNamesIn(src) {
    const names = new Set();
    const re = /import\s+(?:\{([^}]*)\}|\*\s+as\s+(\w+)|(\w+))\s+from\s+['"]zod(?:\/v[34])?['"]/g; let m;
    while ((m = re.exec(src))) {
      if (m[1]) m[1].split(',').forEach((p) => { const q = p.trim().split(/\s+as\s+/); if (q[0] === 'z' || q[0] === 'zod') names.add((q[1] || q[0]).trim()); });
      if (m[2]) names.add(m[2]); if (m[3]) names.add(m[3]);
    }
    if (/require\(['"]zod['"]\)/.test(src) || /\bz\.object\s*\(/.test(src)) names.add('z');
    return names;
  }

  // Top-level `const NAME = <literal>` (strings and literal objects) so { description: DESC } resolves.
  function collectConsts(t, ctx) {
    const consts = {};
    for (let i = 0; i < t.length - 3; i++) {
      if (t[i].type === 'id' && (t[i].value === 'const' || t[i].value === 'let' || t[i].value === 'var') && t[i + 1].type === 'id') {
        let j = i + 2;
        if (isP(t[j], ':')) j = skipType(t, j + 1);
        if (!isP(t[j], '=')) continue;
        const v = parseValue(t, j + 1, Object.assign({}, ctx, { consts }));
        if (v.value !== SKIP) consts[t[i + 1].value] = { value: v.value, exact: v.exact };
      }
    }
    return consts;
  }

  function zodShapeAt(t, i, ctx) {
    // a raw shape object whose values are zod: returns schema with required list, or z.object(...)
    if (isP(t[i], '{')) {
      const optionalKeys = new Set(); const props = {}; let exact = true; let j = i + 1;
      while (j < t.length && !isP(t[j], '}')) {
        const k = t[j]; if (!(k.type === 'id' || k.type === 'str') || !isP(t[j + 1], ':')) { exact = false; j = skipExpr(t, j); if (isP(t[j], ',')) j++; continue; }
        const v = parseValue(t, j + 2, ctx);
        if (v.value !== SKIP) { props[k.value] = v.value; if (v.optional) optionalKeys.add(String(k.value)); } else exact = false;
        exact = exact && v.exact !== false; j = v.end; if (isP(t[j], ',')) j++;
      }
      const shaped = { type: 'object', properties: props };
      const req = Object.keys(props).filter((k) => !optionalKeys.has(k)); if (req.length) shaped.required = req;
      shaped.additionalProperties = false; shaped.$schema = 'http://json-schema.org/draft-07/schema#';
      return { schema: shaped, end: j + 1, exact };
    }
    const v = parseValue(t, i, ctx);
    if (v.value === SKIP || !v.value || typeof v.value !== 'object') return { schema: null, end: v.end, exact: false };
    if (v.zod && v.value.type === 'object') { const s = Object.assign({}, v.value); s.$schema = 'http://json-schema.org/draft-07/schema#'; if (!('additionalProperties' in s)) s.additionalProperties = false; return { schema: s, end: v.end, exact: v.exact }; }
    return { schema: v.value, end: v.end, exact: v.exact };
  }

  const SDK_CALLS = new Set(['registerTool', 'tool', 'addTool']);
  // Keys that hold a tool's argument schema in hand-rolled tool tables: { name, description, schema: { a: z.string() } }
  const SCHEMA_KEYS = ['inputSchema', 'input_schema', 'parameters', 'schema', 'paramsSchema', 'argsSchema'];
  function extractJs(src) {
    const t = tokenize(src);
    const ctx = { zodNames: zodNamesIn(src) }; ctx.zod = ctx.zodNames.size > 0;
    // zod values also need their optional flag at shape level: patch parseValue result via ctx in zodShapeAt
    ctx.consts = collectConsts(t, ctx);
    const tools = []; const seen = new Set();
    const add = (tool, fidelity, at) => {
      if (!tool || typeof tool.name !== 'string' || !tool.name || seen.has(tool.name)) return;
      seen.add(tool.name); tools.push({ tool, fidelity, line: src.slice(0, at).split('\n').length });
    };
    for (let i = 0; i < t.length; i++) {
      const tok = t[i];
      // 1. SDK calls: X.registerTool('name', { title, description, inputSchema, outputSchema, annotations }, cb)
      //               X.tool('name', 'desc'?, shape?, annotations?, cb)
      // Also a bare call to a wrapper with the same signature: registerTool('name', 'desc', shape, cb).
      const member = isP(tok, '.') && t[i + 1] && t[i + 1].type === 'id' && SDK_CALLS.has(t[i + 1].value) && isP(t[i + 2], '(');
      const bare = !member && tok.type === 'id' && SDK_CALLS.has(tok.value) && tok.value !== 'tool' && isP(t[i + 1], '(') && !(t[i - 1] && (isP(t[i - 1], '.') || (t[i - 1].type === 'id' && (t[i - 1].value === 'function' || t[i - 1].value === 'async'))));
      if (member || bare) {
        let fn = member ? t[i + 1].value : tok.value; let j = member ? i + 3 : i + 2; const at = tok.start;
        if (fn === 'registerTool' && t[j] && t[j].type === 'str' && isP(t[j + 1], ',') && t[j + 2] && (t[j + 2].type === 'str' || t[j + 2].type === 'tpl')) fn = 'tool'; // wrapper with the server.tool signature
        const nameTok = t[j];
        if (fn === 'addTool' && isP(nameTok, '{')) { // FastMCP (TS, punkpeye): addTool({ name, description, parameters: z.object(...), annotations, execute })
          const o = parseObjectWithZod(t, j, ctx);
          if (o.value && o.value.name) { const tool = { name: o.value.name }; if (o.value.description) tool.description = o.value.description; if (o.value.parameters) tool.inputSchema = o.value.parameters; else tool.inputSchema = { type: 'object', properties: {} }; if (o.value.annotations) tool.annotations = o.value.annotations; add(tool, 'derived', at); }
          continue;
        }
        if (!nameTok || nameTok.type !== 'str') continue;
        const tool = { name: nameTok.value }; let exact = true; j++;
        if (!isP(t[j], ',')) continue; j++;
        if (fn === 'registerTool') {
          if (!isP(t[j], '{')) continue;
          const cfg = parseObjectWithZod(t, j, ctx); exact = cfg.exact;
          const c = cfg.value && cfg.value !== SKIP ? cfg.value : {};
          if (c.title) tool.title = c.title;
          if (c.description) tool.description = c.description;
          tool.inputSchema = c.inputSchema || { type: 'object', properties: {} };
          if (c.outputSchema) tool.outputSchema = c.outputSchema;
          if (c.annotations) tool.annotations = c.annotations;
          if (c._meta) tool._meta = c._meta;
          tool.execution = { taskSupport: 'forbidden' };
          add(tool, 'derived', at); continue;
        }
        // server.tool(name, [description], [paramsSchema], [annotations], cb)
        const isConstStr = t[j] && t[j].type === 'id' && ctx.consts[t[j].value] && typeof ctx.consts[t[j].value].value === 'string';
        if ((t[j] && t[j].type === 'str') || isConstStr) { const d = parseValue(t, j, ctx); tool.description = d.value; j = d.end; if (isP(t[j], ',')) j++; }
        else if (t[j] && t[j].type === 'tpl') { exact = false; j = skipExpr(t, j); if (isP(t[j], ',')) j++; }
        if (isP(t[j], '{') || (t[j] && t[j].type === 'id' && ctx.zodNames.has(t[j].value))) {
          const shape = zodShapeAt(t, j, ctx);
          if (shape.schema && isZodShapeLike(shape.schema)) { tool.inputSchema = shape.schema; j = shape.end; exact = exact && shape.exact; if (isP(t[j], ',')) j++; if (isP(t[j], '{')) { const ann = parseValue(t, j, ctx); if (ann.value && ann.value !== SKIP && !Array.isArray(ann.value)) tool.annotations = ann.value; } }
          else if (shape.schema && isAnnotations(shape.schema)) tool.annotations = shape.schema;
        }
        if (!tool.inputSchema) tool.inputSchema = { type: 'object', properties: {} };
        tool.execution = { taskSupport: 'forbidden' }; // what TS SDK 1.2x-1.32 adds to every McpServer tool
        add(tool, 'derived', at); continue;
      }
      // 2. object literals with name + inputSchema (low-level Server with a tools array, or MCPB/snapshot-like data)
      if (isP(tok, '{')) {
        // cheap pre-check: an inputSchema/input_schema key within this object at depth 1
        const close = matchClose(t, i); let has = false;
        for (let k = i + 1, d = 0; k < close; k++) { if (isP(t[k], '{') || isP(t[k], '[') || isP(t[k], '(')) d++; else if (isP(t[k], '}') || isP(t[k], ']') || isP(t[k], ')')) d--; else if (d === 0 && (t[k].type === 'id' || t[k].type === 'str') && SCHEMA_KEYS.includes(t[k].value) && isP(t[k + 1], ':')) { has = true; break; } }
        if (!has) continue;
        const o = parseObjectWithZod(t, i, ctx);
        const v = o.value;
        const key = v && v !== SKIP ? SCHEMA_KEYS.find((k) => v[k] && typeof v[k] === 'object' && !Array.isArray(v[k])) : null;
        // other keys than inputSchema only count with a description, so config objects are not taken for tools
        if (key && typeof v.name === 'string' && (key === 'inputSchema' || key === 'input_schema' || typeof v.description === 'string')) {
          let schema = v[key];
          if (!schema.type && !schema.$ref && !schema.anyOf && !schema.oneOf && !schema.properties) { // a raw zod shape (or {}): as the TS SDK lists it
            const k2 = findKeyToken(t, i, o.end, key);
            const sh = k2 >= 0 && isP(t[k2 + 2], '{') ? zodShapeAt(t, k2 + 2, ctx) : null;
            schema = sh && sh.schema && Object.keys(sh.schema.properties).length ? sh.schema : { type: 'object', properties: {} };
          }
          const tool = { name: v.name }; ['title', 'description'].forEach((k) => { if (v[k] !== undefined) tool[k] = v[k]; });
          tool.inputSchema = schema;
          ['outputSchema', 'annotations', '_meta', 'icons', 'execution'].forEach((k) => { if (v[k] !== undefined) tool[k] = v[k]; });
          add(tool, o.exact && !o.sawZod && (key === 'inputSchema' || key === 'input_schema') ? 'literal' : 'derived', tok.start);
          i = o.end - 1;
        }
      }
    }
    return tools;
  }
  function findKeyToken(t, from, to, key) { for (let k = from + 1, d = 0; k < to; k++) { if (isP(t[k], '{') || isP(t[k], '[') || isP(t[k], '(')) d++; else if (isP(t[k], '}') || isP(t[k], ']') || isP(t[k], ')')) d--; else if (d === 0 && (t[k].type === 'id' || t[k].type === 'str') && t[k].value === key && isP(t[k + 1], ':')) return k; } return -1; }
  function isZodShapeLike(s) { return s && s.type === 'object' && s.properties; }
  function isAnnotations(s) { return s && Object.keys(s).some((k) => /Hint$/.test(k) || k === 'title'); }
  function parseObjectWithZod(t, i, ctx) {
    let sawZod = false;
    const c2 = Object.assign({}, ctx);
    const r = parseObject(t, i, c2);
    // a zod value anywhere in the object makes it derived
    for (let k = i; k < r.end; k++) if (t[k].type === 'id' && ctx.zodNames && ctx.zodNames.has(t[k].value) && isP(t[k + 1], '.')) { sawZod = true; break; }
    // inputSchema given as a raw zod shape { a: z.string() } (registerTool): wrap as an object schema
    if (r.value && r.value !== SKIP) {
      ['inputSchema', 'outputSchema'].forEach((key) => {
        const s = r.value[key];
        if (sawZod && s && typeof s === 'object' && !s.type && !s.$ref && !s.anyOf && !s.oneOf) {
          // find the key in tokens to recover optional flags
          for (let k = i + 1; k < r.end; k++) if ((t[k].type === 'id' || t[k].type === 'str') && t[k].value === key && isP(t[k + 1], ':') && isP(t[k + 2], '{')) { const sh = zodShapeAt(t, k + 2, ctx); if (sh.schema) r.value[key] = sh.schema; break; }
        } else if (sawZod && s && s.type === 'object' && !s.$schema) { r.value[key] = Object.assign({}, s, { additionalProperties: s.additionalProperties === undefined ? false : s.additionalProperties, $schema: 'http://json-schema.org/draft-07/schema#' }); }
      });
    }
    r.sawZod = sawZod;
    return r;
  }

  // ------------------------------------------------------------ Python extraction (@x.tool decorated functions)
  // Mirrors the Python SDK's FastMCP/MCPServer output: properties get a title, the schema a "<fn>Arguments" title.
  function pyTitle(name) { return name.split('_').filter(Boolean).map((w) => w[0].toUpperCase() + w.slice(1)).join(' '); }
  function splitTop(s, sep) {
    const out = []; let d = 0; let cur = ''; let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { cur += c; if (c === '\\') { cur += s[++i] || ''; } else if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; cur += c; continue; }
      if ('([{'.includes(c)) d++; else if (')]}'.includes(c)) d--;
      if (c === sep && d === 0) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    if (cur.trim()) out.push(cur);
    return out.map((x) => x.trim());
  }
  function topLevelEq(s) {
    let d = 0; let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { if (c === '\\') i++; else if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c; else if ('([{'.includes(c)) d++; else if (')]}'.includes(c)) d--;
      else if (c === '=' && d === 0 && s[i + 1] !== '=' && s[i - 1] !== '=' && s[i - 1] !== '!' && s[i - 1] !== '<' && s[i - 1] !== '>') return i;
    }
    return -1;
  }
  function pyLiteral(s) {
    s = s.trim();
    if (/^(["'])(?:\\.|(?!\1).)*\1$/.test(s)) return { v: s.slice(1, -1).replace(/\\(.)/g, '$1') };
    if (/^-?\d+$/.test(s)) return { v: parseInt(s, 10) };
    if (/^-?\d*\.\d+(e-?\d+)?$/i.test(s)) return { v: parseFloat(s) };
    if (s === 'True' || s === 'False') return { v: s === 'True' };
    if (s === 'None') return { v: null };
    if (/^\[.*\]$/.test(s)) { const items = splitTop(s.slice(1, -1), ',').map(pyLiteral); return items.every(Boolean) ? { v: items.map((x) => x.v) } : null; }
    return null;
  }
  function pyKwargs(argstr) { const o = {}; splitTop(argstr, ',').forEach((p) => { const m = /^(\w+)\s*=\s*([\s\S]+)$/.exec(p); if (m) o[m[1]] = m[2]; }); return o; }
  function pyType(tp) {
    tp = tp.trim();
    let m;
    if ((m = /^Annotated\[([\s\S]+)\]$/.exec(tp))) {
      const parts = splitTop(m[1], ','); const s = pyType(parts[0]);
      parts.slice(1).forEach((p) => { const f = /^(?:Field|pydantic\.Field)\(([\s\S]*)\)$/.exec(p); if (f) { const kw = pyKwargs(f[1]); const d = kw.description && pyLiteral(kw.description); if (d) s.schema.description = d.v; const pos = splitTop(f[1], ',')[0]; if (pos && !/=/.test(pos)) { const dv = pyLiteral(pos); if (dv && pos !== '...') { s.default = dv.v; } } if (kw.default) { const dv = pyLiteral(kw.default); if (dv) s.default = dv.v; } ['ge:minimum', 'le:maximum', 'gt:exclusiveMinimum', 'lt:exclusiveMaximum', 'min_length:minLength', 'max_length:maxLength'].forEach((pair) => { const [a, b] = pair.split(':'); if (kw[a]) { const n = pyLiteral(kw[a]); if (n) s.schema[b] = n.v; } }); } else if (/^["']/.test(p)) { const d = pyLiteral(p); if (d) s.schema.description = d.v; } });
      return s;
    }
    if ((m = /^(?:Optional|typing\.Optional)\[([\s\S]+)\]$/.exec(tp))) { const s = pyType(m[1]); return { schema: { anyOf: [s.schema, { type: 'null' }] }, exact: s.exact, nullable: true }; }
    const union = splitTop(tp, '|');
    if (union.length > 1) { const parts = union.map(pyType); return { schema: { anyOf: parts.map((p) => p.schema) }, exact: parts.every((p) => p.exact) }; }
    if ((m = /^(?:Literal|typing\.Literal)\[([\s\S]+)\]$/.exec(tp))) { const vals = splitTop(m[1], ',').map(pyLiteral); if (vals.every(Boolean)) { const vs = vals.map((x) => x.v); const t0 = typeof vs[0] === 'string' ? 'string' : typeof vs[0] === 'number' ? (Number.isInteger(vs[0]) ? 'integer' : 'number') : typeof vs[0] === 'boolean' ? 'boolean' : null; return { schema: vs.length === 1 ? Object.assign({ const: vs[0] }, t0 ? { type: t0 } : {}) : Object.assign({ enum: vs }, t0 ? { type: t0 } : {}), exact: true }; } }
    if ((m = /^(?:list|List|Sequence|typing\.List|set|Set)\[([\s\S]+)\]$/.exec(tp))) { const it = pyType(m[1]); return { schema: { type: 'array', items: it.schema }, exact: it.exact }; }
    if ((m = /^(?:dict|Dict|Mapping)\[([\s\S]+)\]$/.exec(tp))) { const parts = splitTop(m[1], ','); const v = pyType(parts[1] || 'Any'); return { schema: { type: 'object', additionalProperties: v.schema }, exact: v.exact }; }
    const map = { str: 'string', int: 'integer', float: 'number', bool: 'boolean', list: 'array', dict: 'object', List: 'array', Dict: 'object', None: 'null' };
    if (map[tp]) return { schema: map[tp] === 'array' ? { type: 'array', items: {} } : map[tp] === 'object' ? { type: 'object', additionalProperties: true } : { type: map[tp] }, exact: true };
    if (tp === 'Any' || tp === 'typing.Any') return { schema: {}, exact: true };
    if (tp === 'datetime' || tp === 'datetime.datetime') return { schema: { type: 'string', format: 'date-time' }, exact: true };
    return { schema: {}, exact: false }; // a model or enum class: the SDK would emit a $ref into $defs
  }
  const CTX_TYPES = /^(Context|mcp\.server\.fastmcp\.Context|ServerContext|RequestContext)\b/;
  function extractPy(src) {
    const tools = []; const lines = src.split('\n');
    const decoRe = /^(\s*)@(\w+)\.tool\s*(\(([\s\S]*?)\))?\s*$/;
    for (let i = 0; i < lines.length; i++) {
      // decorator may span lines: join until balanced parens
      const head = lines[i];
      if (!/^\s*@\w+\.tool\b/.test(head)) continue;
      let deco = head; let j = i;
      while ((deco.split('(').length - deco.split(')').length) > 0 && j < lines.length - 1) deco += '\n' + lines[++j];
      const dm = decoRe.exec(deco); if (!dm) continue;
      const kw = dm[4] ? pyKwargs(dm[4]) : {};
      // skip other decorators, then def
      let k = j + 1; while (k < lines.length && /^\s*@/.test(lines[k])) k++;
      let sig = ''; let e = k;
      for (; e < lines.length; e++) { sig += lines[e] + '\n'; if (/\)\s*(->\s*[^:]+)?:\s*(#.*)?$/.test(lines[e]) && (sig.split('(').length - sig.split(')').length) <= 0) break; }
      const fm = /^\s*(?:async\s+)?def\s+(\w+)\s*\(([\s\S]*)\)\s*(?:->\s*([\s\S]+?))?:\s*(?:#.*)?$/.exec(sig.trim()); if (!fm) continue;
      const fname = fm[1];
      // docstring
      let doc = null; const body = lines.slice(e + 1, e + 80).join('\n');
      const dsm = /^\s*(?:[rubRUB]{0,2})("""|''')([\s\S]*?)\1/.exec(body) || /^\s*(["'])((?:\\.|(?!\1).)*)\1/.exec(body);
      if (dsm) doc = dedent(dsm[2]) + (/\n[ \t]*$/.test(dsm[2]) ? '\n' : '');
      const props = {}; const required = []; let exact = true;
      splitTop(fm[2], ',').forEach((p) => {
        if (!p || p === 'self' || p === 'cls' || p === '*' || p === '/' || /^\*\*?/.test(p)) { if (/^\*\*?\w/.test(p)) exact = false; return; }
        const eq = topLevelEq(p); const lhs = eq < 0 ? p : p.slice(0, eq); const def = eq < 0 ? undefined : p.slice(eq + 1).trim();
        const pm = /^(\w+)\s*(?::\s*([\s\S]+))?$/.exec(lhs.trim()); if (!pm) { exact = false; return; }
        const pn = pm[1]; const tp = pm[2];
        if (tp && CTX_TYPES.test(tp.trim())) return;
        const ty = tp ? pyType(tp) : { schema: {}, exact: false };
        exact = exact && ty.exact;
        const sch = Object.assign({}, ty.schema); const ordered = {};
        if (ty.default !== undefined) ordered.default = ty.default;
        ordered.title = pyTitle(pn);
        const out = Object.assign({}, sch, ordered);
        let hasDefault = ty.default !== undefined;
        if (def !== undefined) { const d = pyLiteral(def); if (d) out.default = d.v; else if (!/^Field\(/.test(def.trim())) exact = false; hasDefault = true; if (/^Field\(/.test(def.trim())) { const fk = pyKwargs(def.trim().slice(6, -1)); if (fk.description) { const dd = pyLiteral(fk.description); if (dd) out.description = dd.v; } if (fk.default) { const dv = pyLiteral(fk.default); if (dv) out.default = dv.v; } else { const pos = splitTop(def.trim().slice(6, -1), ',')[0]; if (pos === '...') hasDefault = false; else { const dv = pos && !/=/.test(pos) ? pyLiteral(pos) : null; if (dv) out.default = dv.v; } } } }
        props[pn] = out; if (!hasDefault) required.push(pn);
      });
      const name = kw.name ? (pyLiteral(kw.name) || {}).v : fname;
      if (typeof name !== 'string') { i = e; continue; } // name=SOME_CONSTANT: not knowable without running it
      const tool = { name };
      const title = kw.title && pyLiteral(kw.title); if (title) tool.title = title.v;
      const desc = kw.description ? pyLiteral(kw.description) : null;
      if (desc) tool.description = desc.v; else if (doc) tool.description = doc;
      tool.inputSchema = { properties: props, required: required.length ? required : undefined, title: fname + 'Arguments', type: 'object' };
      if (!required.length) delete tool.inputSchema.required;
      // Return annotation -> the SDK's structured output schema: {"result": <type>} wrapped as "<fn>Output".
      const ret = fm[3] && fm[3].trim();
      if (ret && !/^None$/.test(ret)) {
        const rt = pyType(ret.replace(/^(?:Awaitable|Coroutine)\[[\s\S]*,\s*([\s\S]+)\]$/, '$1'));
        if (rt.exact && !(rt.schema.type === 'object')) tool.outputSchema = { properties: { result: Object.assign({}, rt.schema, { title: 'Result' }) }, required: ['result'], title: fname + 'Output', type: 'object' };
        else if (!rt.exact) exact = false;
      }
      if (kw.annotations) { const a = pyAnnotations(kw.annotations); if (a) tool.annotations = a; else exact = false; }
      tools.push({ tool, fidelity: 'derived', exactTypes: exact, line: i + 1 });
      i = e;
    }
    return tools;
  }
  function pyAnnotations(s) {
    s = s.trim(); let m;
    if ((m = /^ToolAnnotations\(([\s\S]*)\)$/.exec(s))) { const kw = pyKwargs(m[1]); const o = {}; Object.keys(kw).forEach((k) => { const v = pyLiteral(kw[k]); if (v) o[k] = v.v; }); return o; } // keys as written: the v1 SDK keeps snake_case kwargs as extra fields
    if ((m = /^\{([\s\S]*)\}$/.exec(s))) { const o = {}; splitTop(m[1], ',').forEach((p) => { const kv = splitTop(p, ':'); if (kv.length === 2) { const k = pyLiteral(kv[0]); const v = pyLiteral(kv[1]); if (k && v) o[k.v] = v.v; } }); return o; }
    return null;
  }
  function dedent(s) {
    const ls = s.replace(/^\n/, '').split('\n'); const ind = Math.min(...ls.slice(1).filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length).concat([1e9]));
    return [ls[0].trim()].concat(ls.slice(1).map((l) => (ind < 1e9 ? l.slice(ind) : l))).join('\n').trim();
  }

  // ------------------------------------------------------------ committed lists and manifests
  function toolsFromJson(text) {
    let d; try { d = JSON.parse(text); } catch (e) { return null; }
    if (Array.isArray(d) && d.length && d.every((x) => x && typeof x.name === 'string' && (x.inputSchema || x.input_schema))) return d;
    if (d && Array.isArray(d.tools) && d.tools.length && d.tools.every((x) => x && typeof x.name === 'string' && x.inputSchema)) return d.tools;
    if (d && d.result && Array.isArray(d.result.tools)) return d.result.tools;
    if (d && typeof d.name === 'string' && d.inputSchema) return [d]; // a single-tool snapshot file (a __toolsnaps__ folder)
    return null;
  }
  function fromMcpbManifest(text) {
    let d; try { d = JSON.parse(text); } catch (e) { return null; }
    if (!d || typeof d !== 'object' || !d.server || !d.manifest_version && !d.dxt_version) return null;
    const metas = d._meta && typeof d._meta === 'object' ? Object.values(d._meta) : [];
    for (const m of metas) { const tl = m && m.static_responses && m.static_responses['tools/list']; if (tl && Array.isArray(tl.tools)) return { fidelity: 'exact', tools: tl.tools, generated: !!d.tools_generated }; }
    if (Array.isArray(d.tools) && d.tools.length) return { fidelity: 'names', tools: d.tools.filter((x) => x && x.name).map((x) => ({ name: x.name, description: x.description })), generated: !!d.tools_generated };
    return null;
  }

  // Classify every file of a repo listing; returns the paths worth fetching, best first.
  const SKIP_DIR = /(^|\/)(node_modules|dist|build|out|\.next|vendor|coverage|__pycache__|\.venv|venv|site-packages|examples?|docs?|fixtures?)\//i;
  const TEST_FILE = /(^|\/)(tests?|__tests__|spec)\/|\.(test|spec)\.[jt]sx?$|(^|\/)test_[^/]*\.py$|_test\.py$/i;
  function planFiles(paths) {
    const exact = []; const manifests = []; const serverJson = []; const src = [];
    paths.forEach((p) => {
      const q = p.replace(/^\//, '');
      if (/(^|\/)__toolsnaps__\/[^/]+\.snap$/.test(q)) exact.push(q);
      else if (!SKIP_DIR.test(q) && /(^|\/)(tools(-list|_list)?|mcp-tools|tool-list)\.json$/i.test(q)) exact.push(q);
      else if (!SKIP_DIR.test(q) && /(^|\/)manifest\.json$/.test(q)) manifests.push(q);
      else if (/(^|\/)server\.json$/.test(q) && !SKIP_DIR.test(q)) serverJson.push(q);
      else if (!SKIP_DIR.test(q) && !TEST_FILE.test(q) && /\.(ts|mts|cts|js|mjs|cjs|py)$/.test(q) && !/\.d\.ts$/.test(q) && !/\.min\.js$/.test(q)) src.push(q);
    });
    // likely tool files first
    const score = (p) => (/(^|\/)(tools?|server|index|main|mcp|handlers?)[^/]*\.(ts|js|py|mjs)$/i.test(p) ? 0 : /tool/i.test(p) ? 1 : 2) + p.split('/').length * 0.01;
    src.sort((a, b) => score(a) - score(b));
    return { exact, manifests, serverJson, src };
  }

  function extractFromFile(path, text) {
    if (/\.py$/.test(path)) return extractPy(text);
    if (/\.(ts|mts|cts|js|mjs|cjs)$/.test(path)) return extractJs(text);
    return [];
  }

  // ------------------------------------------------------------ network
  function parseRepoRef(input) {
    const s = String(input || '').trim().replace(/\.git$/, '');
    let m = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)(?:\/(?:tree|blob)\/([^/]+)(\/.*)?)?\/?$/.exec(s);
    if (!m) m = /^([\w.-]+)\/([\w.-]+)$/.exec(s);
    if (!m) return null;
    return { owner: m[1], repo: m[2], ref: m[3] || null, subdir: m[4] ? m[4].replace(/^\/|\/$/g, '') : null };
  }

  const MAX_FILE = 1536 * 1024;      // a source file or committed list
  const MAX_JSON = 16 * 1024 * 1024; // an API answer (a recursive tree listing of a large repository)
  // The body as text, at most `cap` bytes; a longer body is refused, not cut.
  async function readCapped(r, cap, url) {
    const len = Number(r.headers && typeof r.headers.get === 'function' ? r.headers.get('content-length') : 0);
    const big = () => { const e = new Error('Answer over ' + Math.round(cap / 1024) + ' KiB for ' + url); e.code = 'too_large'; return e; };
    if (len && len > cap) throw big();
    if (r.body && typeof r.body.getReader === 'function') {
      const reader = r.body.getReader(); const dec = new TextDecoder(); let n = 0; let t = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.byteLength;
        if (n > cap) { try { await reader.cancel(); } catch (e) { /* ignore */ } throw big(); }
        t += dec.decode(value, { stream: true });
      }
      return t + dec.decode();
    }
    const t = await r.text();
    if (t.length > cap) throw big();
    return t;
  }
  async function getJson(f, url, headers) { const r = await f(url, { headers: headers || {}, credentials: 'omit', redirect: 'follow' }); if (!r.ok) { const e = new Error('HTTP ' + r.status + ' for ' + url); e.status = r.status; throw e; } return JSON.parse(await readCapped(r, MAX_JSON, url)); }
  async function getText(f, url) { const r = await f(url, { credentials: 'omit' }); if (!r.ok) { const e = new Error('HTTP ' + r.status + ' for ' + url); e.status = r.status; throw e; } return readCapped(r, MAX_FILE, url); }

  async function listRepo(f, ref, opts) {
    const gh = { Accept: 'application/vnd.github+json' };
    if (opts.githubToken) gh.Authorization = 'Bearer ' + opts.githubToken;
    try {
      const info = ref.ref ? null : await getJson(f, 'https://api.github.com/repos/' + ref.owner + '/' + ref.repo, gh);
      const branch = ref.ref || info.default_branch;
      const tree = await getJson(f, 'https://api.github.com/repos/' + ref.owner + '/' + ref.repo + '/git/trees/' + encodeURIComponent(branch) + '?recursive=1', gh);
      const sha = tree.sha;
      return { via: 'github', sha, paths: tree.tree.filter((x) => x.type === 'blob' && (!x.size || x.size < 1500000)).map((x) => x.path), truncated: !!tree.truncated, raw: (p) => 'https://raw.githubusercontent.com/' + ref.owner + '/' + ref.repo + '/' + sha + '/' + p.split('/').map(encodeURIComponent).join('/') };
    } catch (e) {
      if (opts.noFallback) throw e;
      // rate limited (403/429) or blocked: jsDelivr (no per-user limit; may lag a branch by hours)
      const v = ref.ref || 'HEAD';
      const d = await getJson(f, 'https://data.jsdelivr.com/v1/packages/gh/' + ref.owner + '/' + ref.repo + '@' + encodeURIComponent(v) + '?structure=flat');
      const ver = d.version || v;
      return { via: 'jsdelivr', sha: ver, paths: d.files.map((x) => x.name.replace(/^\//, '')), truncated: false, raw: (p) => 'https://cdn.jsdelivr.net/gh/' + ref.owner + '/' + ref.repo + '@' + ver + '/' + p };
    }
  }

  async function fromGitHub(input, opts) {
    opts = opts || {};
    const f = opts.fetch || fetch;
    const ref = parseRepoRef(input);
    if (!ref) throw new Error('Not a GitHub repository URL.');
    const listing = await listRepo(f, ref, opts);
    let paths = listing.paths;
    if (ref.subdir) paths = paths.filter((p) => p === ref.subdir || p.startsWith(ref.subdir + '/'));
    const plan = planFiles(paths);
    const maxSrc = opts.maxSourceFiles || 60;
    const candidates = []; const hints = { serverJson: [] };
    const fetchMany = async (ps, n) => {
      const out = []; let k = 0;
      const worker = async () => { while (k < ps.length) { const p = ps[k++]; try { out.push([p, await getText(f, listing.raw(p))]); } catch (e) { out.push([p, null]); } } };
      await Promise.all(Array.from({ length: Math.min(n, ps.length) }, worker));
      return out;
    };
    // exact lists
    const exactFiles = await fetchMany(plan.exact.slice(0, 400), 8);
    const snaps = exactFiles.filter(([p, t]) => t && /__toolsnaps__/.test(p));
    if (snaps.length) {
      const tools = []; const seen = new Set();
      snaps.sort((a, b) => a[0].length - b[0].length).forEach(([p, t]) => { const ts = toolsFromJson(t); (ts || []).forEach((x) => { if (!seen.has(x.name)) { seen.add(x.name); tools.push(x); } }); });
      if (tools.length) candidates.push({ kind: 'snapshots', fidelity: 'exact', path: snaps[0][0].replace(/[^/]+$/, ''), tools });
    }
    exactFiles.filter(([p, t]) => t && !/__toolsnaps__/.test(p)).forEach(([p, t]) => { const ts = toolsFromJson(t); if (ts && ts.length) candidates.push({ kind: 'committed', fidelity: 'exact', path: p, tools: ts }); });
    for (const [p, t] of await fetchMany(plan.manifests.slice(0, 10), 4)) { const m = t && fromMcpbManifest(t); if (m) candidates.push({ kind: 'mcpb', fidelity: m.fidelity, path: p, tools: m.tools, generated: m.generated }); }
    for (const [p, t] of await fetchMany(plan.serverJson.slice(0, 5), 4)) { try { const d = JSON.parse(t); if (d && d.name) hints.serverJson.push({ path: p, name: d.name, remotes: d.remotes || [], packages: d.packages || [] }); } catch (e) { /* ignore */ } }
    // source extraction
    const srcFiles = await fetchMany(plan.src.slice(0, maxSrc), 8);
    const found = []; const byName = new Set();
    srcFiles.forEach(([p, t]) => { if (!t || t.length > 600000) return; let ts = []; try { ts = extractFromFile(p, t); } catch (e) { ts = []; } ts.forEach((x) => { if (!byName.has(x.tool.name)) { byName.add(x.tool.name); found.push(Object.assign({ path: p }, x)); } }); });
    if (found.length) {
      const allLiteral = found.every((x) => x.fidelity === 'literal');
      candidates.push({ kind: 'source', fidelity: allLiteral ? 'literal' : 'derived', path: null, files: Array.from(new Set(found.map((x) => x.path))), tools: found.map((x) => x.tool), where: found.map((x) => ({ name: x.tool.name, path: x.path, line: x.line, fidelity: x.fidelity })) });
    }
    const rank = { exact: 0, literal: 1, derived: 2, names: 3 };
    candidates.sort((a, b) => rank[a.fidelity] - rank[b.fidelity] || b.tools.length - a.tools.length);
    return { repo: ref.owner + '/' + ref.repo, ref: ref.ref, sha: listing.sha, via: listing.via, truncated: listing.truncated, scanned: { exact: plan.exact.length, manifests: plan.manifests.length, source: Math.min(plan.src.length, maxSrc), sourceTotal: plan.src.length }, candidates, best: candidates[0] || null, hints };
  }

  // Registry: name -> latest server.json. The registry's search is a substring match on the name.
  async function fromRegistry(name, opts) {
    opts = opts || {};
    const f = opts.fetch || fetch;
    const base = opts.registry || 'https://registry.modelcontextprotocol.io';
    const d = await getJson(f, base + '/v0/servers?search=' + encodeURIComponent(name) + '&version=latest&limit=30');
    const hit = (d.servers || []).map((x) => x.server).find((s) => s && s.name === name);
    if (!hit) return { name, found: false, similar: (d.servers || []).map((x) => x.server && x.server.name).filter(Boolean).slice(0, 10) };
    const remotes = (hit.remotes || []).filter((r) => r && r.url).map((r) => ({ type: r.type, url: r.url, templated: /\{/.test(r.url), needsHeaders: Array.isArray(r.headers) && r.headers.some((h) => h.isRequired) }));
    const packages = (hit.packages || []).map((p) => ({ registryType: p.registryType, identifier: p.identifier, version: p.version, transport: p.transport && p.transport.type, command: commandFor(p) }));
    return { name, found: true, title: hit.title || null, description: hit.description || null, version: hit.version, repository: hit.repository && hit.repository.url ? hit.repository : null, remotes, packages };
  }
  function commandFor(p) {
    const v = p.version ? p.version : null;
    if (p.registryType === 'npm') return 'npx -y ' + p.identifier + (v ? '@' + v : '');
    if (p.registryType === 'pypi') return 'uvx ' + p.identifier + (v ? '==' + v : '');
    if (p.registryType === 'oci') return 'docker run -i --rm ' + p.identifier + (v && !/:/.test(p.identifier) ? ':' + v : '');
    if (p.registryType === 'nuget') return 'dnx ' + p.identifier + (v ? '@' + v : '') + ' --yes';
    if (p.registryType === 'cargo') return null;
    return null;
  }

  return { fromGitHub, fromRegistry, extractFromFile, extractJs, extractPy, planFiles, parseRepoRef, toolsFromJson, fromMcpbManifest, tokenize, commandFor };
});
