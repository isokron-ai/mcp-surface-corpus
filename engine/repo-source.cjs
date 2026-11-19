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
    } else if (tok.type === 'id' && ctx && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, tok.value) && isP(t[i + 1], '.') && t[i + 2] && t[i + 2].type === 'id' && t[i + 2].value === 'shape' && !isP(t[i + 3], '(') && !isP(t[i + 3], '.')) {
      // Schema.shape of a zod object constant: the raw shape, with the optional flags the object schema kept.
      const c = ctx.consts[tok.value]; const sch = c.value;
      if (c.zod && sch && sch.type === 'object' && sch.properties) { const req = new Set(sch.required || []); r = { value: sch.properties, end: i + 3, exact: c.exact, rawShape: true, optionalKeys: new Set(Object.keys(sch.properties).filter((k) => !req.has(k))) }; }
    } else if (tok.type === 'id' && ctx && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, tok.value) && !isP(t[i + 1], '.') && !isP(t[i + 1], '(')) {
      const c = ctx.consts[tok.value];
      r = { value: c.value, end: i + 1, exact: c.exact, optional: c.optional, zod: c.zod, optionalKeys: c.optionalKeys };
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
      if (isP(k, '...')) {
        // {...NAME}: a constant holding a plain object (this file's, or another file's when the caller supplied them) is merged in.
        const nx = t[i + 1]; const c = nx && nx.type === 'id' && ctx && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, nx.value) ? ctx.consts[nx.value] : null;
        if (c && !c.zod && c.value && typeof c.value === 'object' && !Array.isArray(c.value) && (isP(t[i + 2], ',') || isP(t[i + 2], '}'))) {
          Object.assign(o, c.value); exact = exact && c.exact !== false; if (c.optionalKeys) c.optionalKeys.forEach((x) => optionalKeys.add(x));
          i += isP(t[i + 2], ',') ? 3 : 2; continue;
        }
        exact = false; i = skipExpr(t, i + 1); if (isP(t[i], ',')) i++; continue;
      }
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
      if (v.value !== SKIP) { o[key] = v.value; exact = exact && v.exact !== false; } else if (!HANDLER_KEYS.has(key)) { exact = false; if (ctx && ctx.placeholder) o[key] = {}; }
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
        // the properties of z.object({...}) that cannot be read keep their name (an empty schema) rather than vanish
        const actx = /^(object|strictObject|looseObject)$/.test(name) && !calls.length ? Object.assign({}, ctx, { placeholder: true }) : ctx;
        while (k < close) { const v = parseValue(t, k, actx); args.push(v); k = v.end; if (isP(t[k], ',')) k++; else break; }
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
      case 'object': case 'strictObject': case 'looseObject': { const sh = argv(0); const r = shapeToSchema(sh && sh !== SKIP ? sh : {}, base.args[0] ? base.args[0].optionalKeys : null, ctx && ctx.fl); if (base.name === 'strictObject') r.schema.additionalProperties = false; s = r.schema; if (!sh || sh === SKIP || base.args[0].exact === false) exact = false; break; }
      case 'record': { const v = base.args.length > 1 ? argv(1) : argv(0); s = { type: 'object', additionalProperties: v && v !== SKIP ? v : {} }; if (ctx && ctx.fl && ctx.fl.zod >= 4) { const kk = base.args.length > 1 ? argv(0) : { type: 'string' }; s = { type: 'object', propertyNames: kk && kk !== SKIP ? kk : { type: 'string' }, additionalProperties: s.additionalProperties }; } break; }
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
    const fl = ctx && ctx.fl;
    if (fl && fl.intBounds && s.type === 'integer') { // zod 4 gives an integer the safe-integer range unless the schema narrows it
      if (s.minimum === undefined && s.exclusiveMinimum === undefined) s.minimum = -SAFE_INT;
      if (s.maximum === undefined && s.exclusiveMaximum === undefined) s.maximum = SAFE_INT;
    }
    return { schema: s, exact, optional };
  }
  // A zod raw shape { a: z.string(), b: z.number().optional() } -> object schema the way the TS SDK emits it.
  // What the TS SDK lists for a zod schema depends on the SDK major and the zod major (see tsFlavour):
  //   SDK 1.x + zod 3 (zod-to-json-schema): draft-07, objects closed (additionalProperties: false).
  //   zod 4 (z.toJSONSchema, input mode):    objects open, integers carry the safe-integer bounds; draft-07 under SDK 1.x, 2020-12 under SDK 2.x.
  const SAFE_INT = 9007199254740991;
  const DIALECT = { 'draft-07': 'http://json-schema.org/draft-07/schema#', '2020-12': 'https://json-schema.org/draft/2020-12/schema' };
  const FL_DEFAULT = { dialect: 'draft-07', closed: true, intBounds: false, execution: false, kind: null };
  function shapeToSchema(shape, optionalKeys, fl) {
    const props = {}; const required = [];
    Object.keys(shape || {}).forEach((k) => {
      const v = shape[k];
      props[k] = v; if (!(optionalKeys && optionalKeys.has(k))) required.push(k);
    });
    const s = { type: 'object', properties: props };
    if (required.length) s.required = required;
    if (!fl || fl.closed) s.additionalProperties = false;
    return { schema: s };
  }
  // The root schema of a raw shape or a zod object.
  function rootSchema(props, optionalKeys, fl) {
    const f = fl || FL_DEFAULT;
    const shaped = { type: 'object', properties: props };
    const req = Object.keys(props).filter((k) => !(optionalKeys && optionalKeys.has(k))); if (req.length) shaped.required = req;
    if (f.closed) shaped.additionalProperties = false;
    shaped.$schema = DIALECT[f.dialect];
    return shaped;
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
  // Brace/paren depth before token i: top-level constants only (a const inside a function body is not shared).
  function depthAt(t, i) { let d = 0; for (let k = 0; k < i; k++) { const v = t[k].type === 'p' ? t[k].value : null; if (v === '{' || v === '(' || v === '[') d++; else if (v === '}' || v === ')' || v === ']') d--; } return d; }
  function collectConsts(t, ctx) {
    const consts = Object.assign({}, ctx.globalConsts || {});
    for (let i = 0; i < t.length - 3; i++) {
      if (t[i].type === 'id' && (t[i].value === 'const' || t[i].value === 'let' || t[i].value === 'var') && t[i + 1].type === 'id') {
        let j = i + 2;
        if (isP(t[j], ':')) j = skipType(t, j + 1);
        if (!isP(t[j], '=')) continue;
        const v = parseValue(t, j + 1, Object.assign({}, ctx, { consts }));
        if (v.value !== SKIP) consts[t[i + 1].value] = { value: v.value, exact: v.exact, optional: !!v.optional, zod: !!v.zod, optionalKeys: v.optionalKeys || null, top: depthAt(t, i) === 0 };
      }
    }
    return consts;
  }

  function zodShapeAt(t, i, ctx) {
    // a raw shape object whose values are zod: returns schema with required list, or z.object(...)
    if (isP(t[i], '{')) {
      const optionalKeys = new Set(); const props = {}; let exact = true; let j = i + 1;
      while (j < t.length && !isP(t[j], '}')) {
        if (isP(t[j], '...')) { // {...SHARED, a: z.string()}
          const nx = t[j + 1]; const c = nx && nx.type === 'id' && ctx.consts && Object.prototype.hasOwnProperty.call(ctx.consts, nx.value) ? ctx.consts[nx.value] : null;
          if (c && !c.zod && c.value && typeof c.value === 'object' && !Array.isArray(c.value) && (isP(t[j + 2], ',') || isP(t[j + 2], '}'))) { Object.assign(props, c.value); exact = exact && c.exact !== false; if (c.optionalKeys) c.optionalKeys.forEach((x) => optionalKeys.add(x)); j += isP(t[j + 2], ',') ? 3 : 2; continue; }
          exact = false; j = skipExpr(t, j + 1); if (isP(t[j], ',')) j++; continue;
        }
        const k = t[j]; if (!(k.type === 'id' || k.type === 'str') || !isP(t[j + 1], ':')) { exact = false; j = skipExpr(t, j); if (isP(t[j], ',')) j++; continue; }
        const v = parseValue(t, j + 2, ctx);
        if (v.value !== SKIP) { props[k.value] = v.value; if (v.optional) optionalKeys.add(String(k.value)); } else { exact = false; props[k.value] = {}; }
        exact = exact && v.exact !== false; j = v.end; if (isP(t[j], ',')) j++;
      }
      return { schema: rootSchema(props, optionalKeys, ctx.fl), end: j + 1, exact };
    }
    const v = parseValue(t, i, ctx);
    if (v.value === SKIP || !v.value || typeof v.value !== 'object') return { schema: null, end: v.end, exact: false };
    if (v.rawShape) return { schema: rootSchema(v.value, v.optionalKeys, ctx.fl), end: v.end, exact: v.exact };
    if (v.zod && v.value.type === 'object') { const s = Object.assign({}, v.value); s.$schema = DIALECT[(ctx.fl || FL_DEFAULT).dialect]; return { schema: s, end: v.end, exact: v.exact }; }
    return { schema: v.value, end: v.end, exact: v.exact };
  }

  const SDK_CALLS = new Set(['registerTool', 'tool', 'addTool']);
  // Keys that hold a tool's argument schema in hand-rolled tool tables: { name, description, schema: { a: z.string() } }
  const SCHEMA_KEYS = ['inputSchema', 'input_schema', 'parameters', 'schema', 'paramsSchema', 'argsSchema'];
  // The SDK a TypeScript file is written against, from its imports first and the repository's dependencies second
  // (opts.sdk = { kind: 'v1' | 'v2', version, zod }, see detectSdk). Unknown stays at the zod 3 / SDK 1 reading the reader always had.
  //   execution: SDK 1.24 to 1.x adds { taskSupport: 'forbidden' } to every McpServer tool; earlier 1.x and 2.x do not.
  function semver(v) { const m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(v || '')); return m ? [Number(m[1]), Number(m[2]), Number(m[3] || 0)] : null; }
  function tsFlavour(src, sdk) {
    sdk = sdk || {};
    let kind = null;
    if (/['"]@modelcontextprotocol\/server(?:\/[^'"]*)?['"]/.test(src)) kind = 'v2';
    else if (/['"]@modelcontextprotocol\/sdk(?:\/[^'"]*)?['"]/.test(src)) kind = 'v1';
    else if (sdk.kind === 'v1' || sdk.kind === 'v2') kind = sdk.kind;
    let zod = /from\s+['"]zod\/v4['"]/.test(src) ? 4 : /from\s+['"]zod\/v3['"]/.test(src) ? 3 : (sdk.zod || null);
    if (!zod) zod = kind === 'v2' ? 4 : 3;
    const v = semver(sdk.version);
    const sameKind = !sdk.kind || sdk.kind === kind;
    return { kind, zod, dialect: kind === 'v2' ? '2020-12' : 'draft-07', closed: zod < 4, intBounds: zod >= 4, execution: kind === 'v1' && sameKind && !!v && v[0] === 1 && (v[1] >= 24) };
  }
  function extractJs(src, opts) {
    opts = opts || {};
    const t = tokenize(src);
    const ctx = { zodNames: zodNamesIn(src), fl: tsFlavour(src, opts.sdk), globalConsts: opts.consts || null }; ctx.zod = ctx.zodNames.size > 0;
    // zod values also need their optional flag at shape level: patch parseValue result via ctx in zodShapeAt
    ctx.consts = collectConsts(t, ctx);
    const tools = []; const seen = new Set();
    const add = (tool, fidelity, at, extra) => {
      if (!tool || typeof tool.name !== 'string' || !tool.name || seen.has(tool.name)) return;
      seen.add(tool.name); tools.push(Object.assign({ tool, fidelity, line: src.slice(0, at).split('\n').length, offset: at }, extra || {}));
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
          // FastMCP (TypeScript) lists its zod parameters draft-07 with closed objects, whatever SDK it sits on
          const actx = Object.assign({}, ctx, { fl: Object.assign({}, ctx.fl, { dialect: 'draft-07', closed: true, execution: false }) });
          const o = parseObjectWithZod(t, j, actx);
          if (o.value && o.value.name) { const tool = { name: o.value.name }; if (o.value.description) tool.description = o.value.description; if (o.value.parameters) { tool.inputSchema = o.value.parameters; if (tool.inputSchema.type === 'object' && !tool.inputSchema.$schema) tool.inputSchema = Object.assign({}, tool.inputSchema, { $schema: DIALECT['draft-07'] }, tool.inputSchema.additionalProperties === undefined ? { additionalProperties: false } : {}); } else tool.inputSchema = { type: 'object', properties: {} }; if (o.value.annotations) tool.annotations = o.value.annotations; add(tool, 'derived', at); }
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
          if (ctx.fl.execution) tool.execution = { taskSupport: 'forbidden' };
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
        if (ctx.fl.execution) tool.execution = { taskSupport: 'forbidden' }; // what TS SDK 1.24 to 1.x adds to every McpServer tool
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
          const bound = isP(t[i - 1], '=') && t[i - 2] && t[i - 2].type === 'id' && t[i - 3] && /^(const|let|var)$/.test(t[i - 3].value) ? t[i - 2].value : null;
          add(tool, o.exact && !o.sawZod && (key === 'inputSchema' || key === 'input_schema') ? 'literal' : 'derived', tok.start, { binding: bound, literal: true });
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
    // a zod value anywhere in the object (or the .shape of a zod constant) makes it derived
    for (let k = i; k < r.end; k++) {
      if (t[k].type === 'id' && ctx.zodNames && ctx.zodNames.has(t[k].value) && isP(t[k + 1], '.')) { sawZod = true; break; }
      if (t[k].type === 'id' && t[k].value === 'shape' && isP(t[k - 1], '.') && t[k - 2] && t[k - 2].type === 'id' && ctx.consts && ctx.consts[t[k - 2].value] && ctx.consts[t[k - 2].value].zod) { sawZod = true; break; }
    }
    // inputSchema given as a raw zod shape { a: z.string() } (registerTool): wrap as an object schema
    if (r.value && r.value !== SKIP) {
      const fl = ctx.fl || FL_DEFAULT;
      ['inputSchema', 'outputSchema'].forEach((key) => {
        const s = r.value[key];
        if (sawZod && s && typeof s === 'object' && !s.type && !s.$ref && !s.anyOf && !s.oneOf) {
          // find the key in tokens to recover optional flags
          for (let k = i + 1; k < r.end; k++) if ((t[k].type === 'id' || t[k].type === 'str') && t[k].value === key && isP(t[k + 1], ':')) { const sh = zodShapeAt(t, k + 2, ctx); if (sh.schema) r.value[key] = sh.schema; break; }
        } else if (sawZod && s && s.type === 'object' && !s.$schema) { r.value[key] = Object.assign({}, s, { $schema: DIALECT[fl.dialect] }, fl.closed && s.additionalProperties === undefined ? { additionalProperties: false } : {}); }
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
    if (/^[A-Za-z_]\w*$/.test(s) && Object.prototype.hasOwnProperty.call(PYC, s)) return { v: PYC[s] };
    if (/^\[.*\]$/.test(s)) { const items = splitTop(s.slice(1, -1), ',').map(pyLiteral); return items.every(Boolean) ? { v: items.map((x) => x.v) } : null; }
    return null;
  }
  function pyKwargs(argstr) { const o = {}; splitTop(argstr, ',').forEach((p) => { const m = /^(\w+)\s*=\s*([\s\S]+)$/.exec(p); if (m) o[m[1]] = m[2]; }); return o; }
  function pyType(tp) {
    tp = tp.trim();
    let m;
    if ((m = /^Annotated\[([\s\S]+)\]$/.exec(tp))) {
      const parts = splitTop(m[1], ','); const s = pyType(parts[0]);
      parts.slice(1).forEach((p) => { const f = /^(?:Field|pydantic\.Field)\(([\s\S]*)\)$/.exec(p); if (f) { const kw = pyKwargs(f[1]); const d = kw.description && pyLiteral(kw.description); if (d) s.schema.description = d.v; const pos = splitTop(f[1], ',')[0]; if (pos && !/=/.test(pos)) { const dv = pyLiteral(pos); if (dv && pos !== '...') { s.default = dv.v; } } if (kw.default) { const dv = pyLiteral(kw.default); if (dv) s.default = dv.v; } pyConstraints(s.schema, kw); } else if (/^["']/.test(p)) { const d = pyLiteral(p); if (d) s.schema.description = d.v; } });
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
  // Module-level NAME = <literal> constants of a Python file, so Field(default=DEFAULT_X) and gt=MIN_X resolve.
  let PYC = {};
  function pyConsts(src) {
    const out = {};
    src.split('\n').forEach((l) => { const m = /^([A-Za-z_]\w*)\s*(?::\s*[^=]+?)?=\s*(.+?)\s*(?:#.*)?$/.exec(l); if (!m) return; const v = pyLiteral(m[2]); if (v) out[m[1]] = v.v; });
    return out;
  }
  // The pydantic keyword constraints of Field(...) / Annotated[..., Field(...)] as JSON Schema keywords.
  function pyConstraints(schema, kw) {
    const arr = schema.type === 'array';
    [['ge', 'minimum'], ['le', 'maximum'], ['gt', 'exclusiveMinimum'], ['lt', 'exclusiveMaximum'], ['min_length', arr ? 'minItems' : 'minLength'], ['max_length', arr ? 'maxItems' : 'maxLength'], ['multiple_of', 'multipleOf'], ['pattern', 'pattern']].forEach(([a, b]) => { if (kw[a] !== undefined) { const n = pyLiteral(kw[a]); if (n) schema[b] = n.v; } });
  }
  // Python flavours: the SDK's FastMCP/MCPServer ("sdk": titles on properties and on the argument model) and the standalone
  // fastmcp package ("fastmcp": no titles, closed argument model, docstring Args become parameter descriptions, _meta.fastmcp.tags).
  function pyFlavour(src, opts) {
    const sdk = opts && opts.sdk && opts.sdk.py;
    if (/^\s*from\s+mcp\.server\.(?:fastmcp|mcpserver)\b/m.test(src) || /^\s*from\s+mcp\b/m.test(src)) return 'sdk';
    if (/^\s*(?:from\s+fastmcp\b|import\s+fastmcp\b)/m.test(src)) return 'fastmcp';
    return sdk === 'fastmcp' ? 'fastmcp' : 'sdk';
  }
  // Google-style docstring: the text before "Args:" is the description; "name: text" lines under Args are parameter descriptions.
  function pyDocSections(doc) {
    const lines = String(doc || '').split('\n'); const head = []; const params = {}; let section = null; let cur = null;
    for (const l of lines) {
      const sec = /^(Args|Arguments|Parameters|Returns|Raises|Yields|Examples?|Notes?):\s*$/.exec(l.trim());
      if (sec && !/^\s{2,}/.test(l.replace(/^\t/, '    ')) || (sec && section === null)) { section = sec[1]; cur = null; continue; }
      if (section === null) { head.push(l); continue; }
      if (/^(Args|Arguments|Parameters)$/.test(section)) {
        const m = /^\s+(\w+)(?:\s*\([^)]*\))?\s*:\s*(.*)$/.exec(l);
        if (m && (cur === null || l.search(/\S/) <= (cur.indent))) { cur = { name: m[1], text: m[2].trim(), indent: l.search(/\S/) }; params[m[1]] = cur; }
        else if (cur && l.trim()) cur.text += '\n' + l.slice(cur.indent).replace(/\s+$/, '');
      }
    }
    const out = {}; Object.keys(params).forEach((k) => { out[k] = params[k].text; });
    return { description: head.join('\n').trim(), params: out, hasSections: section !== null };
  }
  function extractPy(src, opts) {
    const flavour = pyFlavour(src, opts); const fmcp = flavour === 'fastmcp'; PYC = pyConsts(src);
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
        if (!fmcp) ordered.title = pyTitle(pn);
        const out = Object.assign({}, sch, ordered);
        let hasDefault = ty.default !== undefined;
        if (def !== undefined) {
          const field = /^(?:Field|pydantic\.Field)\(([\s\S]*)\)$/.exec(def.trim());
          if (!field) { const d = pyLiteral(def); if (d) out.default = d.v; else exact = false; hasDefault = true; } else {
            // Field(...): a default is a first positional argument other than "..." or default= / default_factory=; without one the parameter is required.
            const fk = pyKwargs(field[1]); const pos = splitTop(field[1], ',')[0]; const posArg = pos && !/^\w+\s*=/.test(pos) ? pos : null;
            hasDefault = false;
            if (posArg !== null) { if (posArg !== '...') { hasDefault = true; const dv = pyLiteral(posArg); if (dv) out.default = dv.v; else exact = false; } }
            else if (fk.default !== undefined) { hasDefault = true; const dv = pyLiteral(fk.default); if (dv) out.default = dv.v; else exact = false; }
            else if (fk.default_factory !== undefined) { hasDefault = true; exact = false; }
            if (fk.description) { const dd = pyLiteral(fk.description); if (dd) out.description = dd.v; else exact = false; }
            if (fk.title && !fmcp) { const tt = pyLiteral(fk.title); if (tt) out.title = tt.v; }
            pyConstraints(out, fk);
          }
        }
        props[pn] = out; if (!hasDefault) required.push(pn);
      });
      const name = kw.name ? (pyLiteral(kw.name) || {}).v : fname;
      if (typeof name !== 'string') { i = e; continue; } // name=SOME_CONSTANT: not knowable without running it
      const tool = { name };
      const title = kw.title && pyLiteral(kw.title); if (title) tool.title = title.v;
      const desc = kw.description ? pyLiteral(kw.description) : null;
      const ds = fmcp && doc ? pyDocSections(doc) : null;
      if (desc) tool.description = desc.v; else if (doc) tool.description = ds ? ds.description : doc;
      if (ds) Object.keys(props).forEach((pn) => { if (props[pn].description === undefined && ds.params[pn]) props[pn].description = ds.params[pn]; });
      tool.inputSchema = fmcp ? { properties: props, required: required.length ? required : undefined, type: 'object', additionalProperties: false } : { properties: props, required: required.length ? required : undefined, title: fname + 'Arguments', type: 'object' };
      if (!required.length) delete tool.inputSchema.required;
      // Return annotation -> the SDK's structured output schema: {"result": <type>} wrapped as "<fn>Output".
      const ret = fm[3] && fm[3].trim();
      if (ret && !/^None$/.test(ret)) {
        const rt = pyType(ret.replace(/^(?:Awaitable|Coroutine)\[[\s\S]*,\s*([\s\S]+)\]$/, '$1'));
        if (fmcp) {
          if (rt.exact && rt.schema.type === 'object') tool.outputSchema = { additionalProperties: true, type: 'object' };
          else if (rt.exact) tool.outputSchema = { properties: { result: rt.schema }, required: ['result'], type: 'object', 'x-fastmcp-wrap-result': true };
          else exact = false;
        } else if (rt.exact && !(rt.schema.type === 'object')) tool.outputSchema = { properties: { result: Object.assign({}, rt.schema, { title: 'Result' }) }, required: ['result'], title: fname + 'Output', type: 'object' };
        else if (!rt.exact) exact = false;
      }
      if (kw.annotations) { const a = pyAnnotations(kw.annotations); if (a) tool.annotations = a; else exact = false; }
      if (fmcp) { if (kw.tags === undefined) tool._meta = { fastmcp: { tags: [] } }; else exact = false; }
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

  // opts: { sdk: { kind, version, zod, py }, consts } as detectSdk and collectGlobalConsts return them.
  function extractFromFile(path, text, opts) {
    if (/\.py$/.test(path)) return extractPy(text, opts);
    if (/\.(ts|mts|cts|js|mjs|cjs)$/.test(path)) return extractJs(text, opts);
    return [];
  }

  // ------------------------------------------------------------ SDK detection, shared constants, whole-repository analysis
  const META_FILE = /(^|\/)(package\.json|package-lock\.json|pyproject\.toml|requirements[^/]*\.txt|uv\.lock)$/;
  // Which SDK a repository builds on, from its manifests. Imports in a file win over this (see tsFlavour, pyFlavour).
  // Returns { kind: 'v1' | 'v2' | null, version, zod, py: 'sdk' | 'fastmcp' | null }. A lock file's exact version beats a range.
  function detectSdk(files) {
    const entries = files instanceof Map ? Array.from(files.entries()) : Object.keys(files || {}).map((k) => [k, files[k]]);
    const depth = (p) => p.split('/').length;
    const out = { kind: null, version: null, zod: null, py: null };
    const pick = (name, dep, lock) => lock || dep || null;
    const rank = (a, b) => depth(a[0]) - depth(b[0]);
    const pkgs = entries.filter(([p]) => /(^|\/)package\.json$/.test(p) && !/node_modules/.test(p)).sort(rank);
    const locks = entries.filter(([p]) => /(^|\/)package-lock\.json$/.test(p) && !/node_modules/.test(p)).sort(rank);
    let server = null; let sdk = null; let zod = null;
    pkgs.forEach(([, text]) => {
      let j; try { j = JSON.parse(text); } catch (e) { return; }
      const deps = Object.assign({}, j.devDependencies, j.peerDependencies, j.dependencies);
      if (!server && deps['@modelcontextprotocol/server']) server = deps['@modelcontextprotocol/server'];
      if (!sdk && deps['@modelcontextprotocol/sdk']) sdk = deps['@modelcontextprotocol/sdk'];
      if (!zod && deps.zod) zod = deps.zod;
    });
    let lock = {};
    locks.forEach(([, text]) => {
      let j; try { j = JSON.parse(text); } catch (e) { return; }
      const pk = j.packages || {};
      ['@modelcontextprotocol/server', '@modelcontextprotocol/sdk', 'zod'].forEach((n) => { const e = pk['node_modules/' + n]; if (e && e.version && !lock[n]) lock[n] = e.version; });
    });
    const sv = pick('server', server, lock['@modelcontextprotocol/server']); const kv = pick('sdk', sdk, lock['@modelcontextprotocol/sdk']); const zv = pick('zod', zod, lock.zod);
    if (sv) { out.kind = 'v2'; out.version = semver(sv) ? semver(sv).join('.') : null; } else if (kv) { const v = semver(kv); out.kind = v && v[0] >= 2 ? 'v2' : 'v1'; out.version = v ? v.join('.') : null; }
    const zm = semver(zv); if (zm) out.zod = zm[0];
    // Python: the standalone fastmcp package, or the SDK's own FastMCP.
    let fast = false; let mcp = false;
    entries.forEach(([p, text]) => {
      if (!/(^|\/)(pyproject\.toml|requirements[^/]*\.txt)$/.test(p) || /(^|\/)(node_modules|\.venv|venv)\//.test(p)) return;
      if (/^\s*["']?fastmcp\b/im.test(text) || /["']fastmcp[\s>=<~!;\[]/i.test(text)) fast = true;
      if (/^\s*["']?mcp\b/im.test(text) || /["']mcp[\s>=<~!;\[]/i.test(text)) mcp = true;
    });
    out.py = fast && !mcp ? 'fastmcp' : fast || mcp ? 'sdk' : null;
    return out;
  }

  // Top-level constants shared across files (a name defined once), so {...SHARED} and Schema.shape resolve across an import.
  function collectGlobalConsts(srcFiles) {
    const seen = {}; const dup = new Set();
    const run = (seed) => {
      const table = {};
      srcFiles.forEach(([p, text]) => {
        if (!/\.(ts|mts|cts|js|mjs|cjs)$/.test(p)) return;
        let t; try { t = tokenize(text); } catch (e) { return; }
        const zn = zodNamesIn(text); const ctx = { zodNames: zn, zod: zn.size > 0, fl: tsFlavour(text, null), globalConsts: seed };
        let cs; try { cs = collectConsts(t, ctx); } catch (e) { return; }
        Object.keys(cs).forEach((k) => {
          if (seed && Object.prototype.hasOwnProperty.call(seed, k) && cs[k] === seed[k]) return;
          const c = cs[k]; if (!c.top || !c.value || typeof c.value !== 'object' || Array.isArray(c.value)) return;
          if (Object.prototype.hasOwnProperty.call(table, k)) { dup.add(k); return; }
          table[k] = c;
        });
      });
      dup.forEach((k) => { delete table[k]; });
      return table;
    };
    const first = run(null);
    const second = run(first);
    Object.keys(first).forEach((k) => { if (!second[k]) second[k] = first[k]; });
    void seen;
    return second;
  }

  // Blocks of a JS/TS token stream: { open, close, kind: 'if' | 'else' | 'fn' | 'other', cond, name }.
  function jsBlocks(src, t) {
    const blocks = []; const stack = [];
    const back = (i) => { let d = 0; for (let k = i; k >= 0; k--) { if (isP(t[k], ')')) d++; else if (isP(t[k], '(')) { d--; if (d === 0) return k; } } return -1; };
    const typeish = (x) => x && (x.type === 'id' || (x.type === 'p' && ['.', '<', '>', '|', '&', '[', ']', ',', '?'].includes(x.value)));
    // the ")" that closes a parameter list ending just before token k, allowing a ": ReturnType" between
    const sigClose = (k) => {
      if (k >= 0 && isP(t[k], ')')) return k;
      for (let m = k, n = 0; m >= 1 && n < 40; m--, n++) { if (isP(t[m], ':') && isP(t[m - 1], ')')) return m - 1; if (!typeish(t[m])) break; }
      return -1;
    };
    for (let i = 0; i < t.length; i++) {
      if (isP(t[i], '{')) {
        let kind = 'other'; let cond = null; let name = null; const pv = t[i - 1];
        const arrow = pv && isP(pv, '=>');
        const c = sigClose(arrow ? i - 2 : i - 1);
        if (arrow || c >= 0) {
          if (c >= 0) {
            const m = back(c); const kw = m > 0 ? t[m - 1] : null;
            if (!arrow && kw && kw.type === 'id' && kw.value === 'if') { kind = 'if'; cond = src.slice(t[m].start + 1, t[c].start).trim(); }
            else if (!arrow && kw && kw.type === 'id' && /^(while|for|switch|catch|with)$/.test(kw.value)) kind = 'other';
            else if (arrow) { kind = 'fn'; let k = m - 1; while (k >= 0 && t[k].type === 'id' && t[k].value === 'async') k--; if (k >= 1 && isP(t[k], '=') && t[k - 1].type === 'id') name = t[k - 1].value; }
            else if (kw && kw.type === 'id') { kind = 'fn'; name = kw.value; }
          } else if (arrow) { kind = 'fn'; let k = i - 2; if (t[k] && t[k].type === 'id') k--; while (k >= 0 && t[k].type === 'id' && t[k].value === 'async') k--; if (k >= 1 && isP(t[k], '=') && t[k - 1].type === 'id') name = t[k - 1].value; }
        } else if (pv && pv.type === 'id' && pv.value === 'else') { kind = 'else'; cond = 'else'; }
        stack.push({ open: i, kind, cond, name });
      } else if (isP(t[i], '}')) {
        const b = stack.pop(); if (b) { b.close = i; blocks.push(b); }
      }
    }
    stack.forEach((b) => { b.close = t.length - 1; blocks.push(b); });
    return blocks;
  }
  function enclosing(blocks, t, offset) {
    return blocks.filter((b) => t[b.open].start < offset && (t[b.close] ? t[b.close].start : Infinity) > offset).sort((a, b) => a.open - b.open);
  }
  // Conditions around an offset, inside its innermost function: [{ kind, cond }] outermost first, plus that function's name.
  function guardsAt(blocks, t, offset) {
    const encl = enclosing(blocks, t, offset);
    let fnIdx = -1; encl.forEach((b, i) => { if (b.kind === 'fn') fnIdx = i; });
    const fn = fnIdx >= 0 ? encl[fnIdx] : null;
    return { fn: fn ? fn.name : null, guards: encl.slice(fnIdx + 1).filter((b) => b.kind === 'if' || b.kind === 'else').map((b) => ({ kind: b.kind, cond: b.cond })) };
  }
  function pyGuards(lines, line) {
    // indentation walk upwards from the decorator: the if/elif/else lines that enclose it
    const guards = []; const indent = (l) => l.search(/\S/); let want = indent(lines[line - 1] || '');
    for (let k = line - 2; k >= 0 && want > 0; k--) {
      const l = lines[k]; if (!l.trim() || /^\s*#/.test(l)) continue;
      const ind = indent(l); if (ind >= want) continue;
      want = ind;
      const m = /^\s*(if|elif|else)\b\s*(.*?):?\s*$/.exec(l);
      if (m && /:\s*(#.*)?$/.test(l)) guards.unshift({ kind: m[1] === 'else' ? 'else' : 'if', cond: m[1] === 'else' ? 'else' : m[2].replace(/:$/, '') });
    }
    return guards;
  }
  const DISABLED_KEYS = [['enabled', false], ['defaultEnabled', false], ['enabledByDefault', false], ['disabled', true], ['hidden', true]];
  const IDENT_RE = (n) => new RegExp('(^|[^\\w$.])' + n.replace(/[$]/g, '\\$') + '(?![\\w$])', 'g');

  // Decorate and filter the tools found in a repository. Reasons that remove a tool from the list the server would send:
  //   disabled-by-default    a literal table keyed by the tool's name says enabled: false (or disabled: true)
  //   declares-conditions    the tool carries a non-empty conditions list (it is registered only when those flags are set)
  //   alternate-server       the tool is only in one of several server modules that register overlapping tools (one is chosen by configuration)
  //   unreferenced-declaration  a { name, description, inputSchema } constant that nothing else in the server mentions
  // Reasons that only mark a tool (the reader cannot know which way the condition goes):
  //   conditional-branch     the registration sits inside an if / else of its own function
  //   conditional-caller     every call of the function that registers it sits inside an if / else
  //   deprecated             the title or description starts by saying so
  function markConditionals(found, files, dupes) {
    const marks = new Map(found.map((f) => [f, []]));
    const add = (f, reason, detail, exclude) => marks.get(f).push({ reason, detail: detail || null, exclude: !!exclude });
    const srcs = new Map(); files.forEach(([p, text]) => srcs.set(p, text));
    const tokCache = new Map(); const blkCache = new Map();
    const tk = (p) => { if (!tokCache.has(p)) { try { tokCache.set(p, tokenize(srcs.get(p))); } catch (e) { tokCache.set(p, []); } } return tokCache.get(p); };
    const bl = (p) => { if (!blkCache.has(p)) blkCache.set(p, jsBlocks(srcs.get(p), tk(p))); return blkCache.get(p); };
    const isJs = (p) => /\.(ts|mts|cts|js|mjs|cjs)$/.test(p);
    const names = new Set(found.map((f) => f.tool.name));

    // branch / caller conditions
    const callSites = new Map();
    const callersOf = (fname) => {
      if (callSites.has(fname)) return callSites.get(fname);
      const out = [];
      srcs.forEach((text, p) => {
        if (!isJs(p) || text.indexOf(fname) < 0) return;
        const t = tk(p);
        for (let i = 0; i < t.length - 1; i++) {
          if (t[i].type === 'id' && t[i].value === fname && isP(t[i + 1], '(') && !(t[i - 1] && t[i - 1].type === 'id' && /^(function|async)$/.test(t[i - 1].value))) {
            // a declaration "NAME(args) {" of a method is not a call
            const close = matchClose(t, i + 1);
            if (isP(t[close + 1], '{') ) continue;
            out.push({ p, guards: guardsAt(bl(p), t, t[i].start).guards });
          }
        }
      });
      callSites.set(fname, out); return out;
    };
    found.forEach((f) => {
      if (isJs(f.path) && f.offset !== undefined) {
        const t = tk(f.path); const g = guardsAt(bl(f.path), t, f.offset);
        if (g.guards.length) add(f, 'conditional-branch', g.guards.map((x) => x.cond).join(' && ').slice(0, 120));
        else if (g.fn) { const calls = callersOf(g.fn); if (calls.length && calls.every((c) => c.guards.length)) add(f, 'conditional-caller', calls[0].guards.map((x) => x.cond).join(' && ').slice(0, 120)); }
      } else if (/\.py$/.test(f.path) && f.line) {
        const gs = pyGuards(srcs.get(f.path).split('\n'), f.line);
        if (gs.length) add(f, 'conditional-branch', gs.map((x) => x.cond).join(' and ').slice(0, 120));
      }
      const a = f.tool.annotations; const conds = (a && Array.isArray(a.conditions) ? a.conditions : null) || (Array.isArray(f.tool.conditions) ? f.tool.conditions : null);
      if (conds && conds.length) add(f, 'declares-conditions', conds.join(', ').slice(0, 120), true);
      const text = String(f.tool.title || '') + ' ' + String(f.tool.description || '').slice(0, 80);
      if (/\bdeprecated\b/i.test(String(f.tool.title || '')) || /^\s*(\(?deprecated\b|\[deprecated\])/i.test(String(f.tool.description || '')) || /\bis deprecated\b/i.test(String(f.tool.description || '').slice(0, 120))) add(f, 'deprecated', null); void text;
    });

    // a literal table keyed by tool names that switches tools off
    srcs.forEach((text, p) => {
      if (!isJs(p) || !/\b(enabled|defaultEnabled|enabledByDefault|disabled|hidden)\b/.test(text)) return;
      const t = tk(p); const ctx = { consts: {}, zodNames: new Set() };
      for (let i = 0; i < t.length - 2; i++) {
        if (!(t[i].type === 'id' || t[i].type === 'str') || !names.has(String(t[i].value)) || !isP(t[i + 1], ':') || !isP(t[i + 2], '{')) continue;
        let o; try { o = parseObject(t, i + 2, ctx); } catch (e) { continue; }
        if (!o.value || o.value === SKIP) continue;
        const hit = DISABLED_KEYS.find(([k, v]) => o.value[k] === v);
        if (hit) found.forEach((f) => { if (f.tool.name === String(t[i].value)) add(f, 'disabled-by-default', hit[0] + ': ' + hit[1] + ' in ' + p, true); });
      }
    });

    // Several modules registering the same tool names are alternatives (one is chosen by configuration at start): keep the
    // module with the most tools, drop the tools only the others have. dupes: the registrations that lost the name to an earlier file.
    const reg = found.map((f) => ({ f, path: f.path, name: f.tool.name })).concat((dupes || []).map((d) => ({ f: null, path: d.path, name: d.name })));
    const filesOf = new Map(); const namesIn = new Map();
    reg.forEach((r) => { if (!filesOf.has(r.name)) filesOf.set(r.name, new Set()); filesOf.get(r.name).add(r.path); if (!namesIn.has(r.path)) namesIn.set(r.path, new Set()); namesIn.get(r.path).add(r.name); });
    const parent = new Map(); const find = (x) => { if (!parent.has(x)) parent.set(x, x); while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
    filesOf.forEach((set) => { const a = Array.from(set); a.slice(1).forEach((x) => parent.set(find(x), find(a[0]))); });
    const comps = new Map(); namesIn.forEach((_, p) => { const r = find(p); if (!comps.has(r)) comps.set(r, []); comps.get(r).push(p); });
    comps.forEach((paths) => {
      if (paths.length < 2) return;
      paths.sort((x, y) => namesIn.get(y).size - namesIn.get(x).size || x.length - y.length || (x < y ? -1 : 1));
      const keep = namesIn.get(paths[0]);
      found.forEach((f) => { if (paths.includes(f.path) && !keep.has(f.tool.name)) add(f, 'alternate-server', f.path + ' is an alternative to ' + paths[0], true); });
    });

    // a literal declaration that no other file or line mentions
    found.forEach((f) => {
      if (!f.literal || !f.binding) return;
      let uses = 0;
      srcs.forEach((text) => { const m = text.match(IDENT_RE(f.binding)); if (m) uses += m.length; });
      if (uses <= 1) add(f, 'unreferenced-declaration', f.binding, true);
    });
    return marks;
  }

  // Everything the reader does with a repository's files: SDK and constants, extraction, marking, exclusion.
  // files: Map(path -> text) or [[path, text]]. Returns { found, tools, excluded, sdk }.
  function analyseRepo(files, opts) {
    opts = opts || {};
    const all = files instanceof Map ? Array.from(files.entries()) : files;
    const paths = all.map(([p]) => p);
    const plan = planFiles(paths);
    const text = new Map(all);
    const sdk = Object.assign({}, detectSdk(text), opts.sdk || {});
    const srcList = plan.src.slice(0, opts.maxSourceFiles || 600).map((p) => [p, text.get(p)]).filter(([, x]) => typeof x === 'string' && x.length <= 600000);
    const consts = collectGlobalConsts(srcList);
    const found = []; const byName = new Set();
    const dupes = [];
    srcList.forEach(([p, t]) => {
      let ts = []; try { ts = extractFromFile(p, t, { sdk, consts }); } catch (e) { ts = []; }
      ts.forEach((x) => { if (!byName.has(x.tool.name)) { byName.add(x.tool.name); found.push(Object.assign({ path: p }, x)); } else dupes.push({ path: p, name: x.tool.name }); });
    });
    const marks = markConditionals(found, srcList, dupes);
    found.forEach((f) => { f.marks = marks.get(f); f.excluded = f.marks.some((m) => m.exclude); });
    // Never return an empty list because of exclusions: the marks stay, the exclusion does not apply.
    if (found.length && found.every((f) => f.excluded)) found.forEach((f) => { f.excluded = false; f.marks.forEach((m) => { m.exclude = false; }); });
    return { found, tools: found.filter((f) => !f.excluded), excluded: found.filter((f) => f.excluded), sdk, plan, files: srcList.length };
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
    // source extraction: the manifests (SDK and zod versions), then the sources, then one analysis over all of them
    const metaPaths = paths.filter((p) => META_FILE.test(p) && !SKIP_DIR.test(p) && p.split('/').length <= (ref.subdir ? ref.subdir.split('/').length : 0) + 2).slice(0, 8);
    const rootMeta = listing.paths.filter((p) => /^(package\.json|package-lock\.json|pyproject\.toml)$/.test(p) && !paths.includes(p));
    const metaFiles = await fetchMany(metaPaths.concat(rootMeta).slice(0, 10), 4);
    const srcFiles = await fetchMany(plan.src.slice(0, maxSrc), 8);
    const repoFiles = new Map(); metaFiles.concat(srcFiles).forEach(([p, t]) => { if (t) repoFiles.set(p, t); });
    const an = analyseRepo(repoFiles, { maxSourceFiles: maxSrc });
    const found = an.tools;
    if (found.length) {
      const allLiteral = found.every((x) => x.fidelity === 'literal');
      const marked = an.found.filter((x) => x.marks.length).map((x) => ({ name: x.tool.name, reasons: x.marks.map((m) => m.reason), excluded: x.excluded }));
      candidates.push({ kind: 'source', fidelity: allLiteral ? 'literal' : 'derived', path: null, files: Array.from(new Set(found.map((x) => x.path))), tools: found.map((x) => x.tool), where: found.map((x) => ({ name: x.tool.name, path: x.path, line: x.line, fidelity: x.fidelity })), excluded: an.excluded.map((x) => ({ name: x.tool.name, path: x.path, line: x.line, reasons: x.marks.filter((m) => m.exclude).map((m) => m.reason + (m.detail ? ' (' + m.detail + ')' : '')) })), marked, sdk: an.sdk });
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

  return { fromGitHub, fromRegistry, extractFromFile, extractJs, extractPy, planFiles, detectSdk, collectGlobalConsts, analyseRepo, markConditionals, parseRepoRef, toolsFromJson, fromMcpbManifest, tokenize, commandFor };
});
