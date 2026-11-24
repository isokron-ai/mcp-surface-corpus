// Reads the syscall trace runsc writes for one container (`--strace`, the families in gvisor.json)
// and keeps a compact summary for the run telemetry: counts by family, file opens outside the
// expected paths, reads of credential paths, programs run, sockets, connections and other network
// attempts, links made (and where they point), and privileged calls. The trace is the target's doing, so every string in it is
// untrusted: paths and addresses are cut to a fixed length and every list is capped.
//
// Known limit: runsc prints path arguments without quoting (Go %s, pkg/sentry/strace path()), so a
// file name with a line break in it can start a line of its own that looks like any other trace
// line, header included. Lines without runsc's log header are ignored, a call line whose argument
// list does not close is counted (`broken_lines`), and either sets `injection_suspected`. Every
// summary says `target_influenced: true`: it is evidence the target could have shaped, never the
// only evidence that something was blocked. Structured trace output is the real fix (follow-up).
import { createReadStream } from 'node:fs';
import { posix } from 'node:path';
import { createInterface } from 'node:readline';
import { parseQuestion } from './dns.mjs';
import { FAMILIES, syscallFamily } from './runsc.mjs';

export const SUMMARY_FORMAT = 'isokron-trace-summary/1';
const HEAD = /^[IWEDF]\d{4} [0-9:.]+\s+\d+\s+[^\s\]]+:\d+\]\s?(.*)$/;
const TASK = /^\[\s*([^\]]*?)\s*\]\s+(.*)$/;
const CALL = /^(.*?) ([EX]) ([a-z0-9_]+)\(/;
const STR_CAP = 200;

/** Finds the argument list of a call: from just after "(" to its matching ")", outside quotes. */
function argSpan(s, from) {
  let depth = 0; let q = false;
  for (let i = from; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\') i++; else if (c === '"') q = false; continue; }
    if (c === '"') q = true;
    else if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') { if (depth === 0) { if (c === ')') return i; return -1; } depth--; }
  }
  return -1;
}

/** Splits arguments at top-level ", ". */
export function splitArgs(s) {
  const out = []; let depth = 0; let q = false; let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\') i++; else if (c === '"') q = false; continue; }
    if (c === '"') q = true;
    else if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') depth--;
    else if (c === ',' && depth === 0 && s[i + 1] === ' ') { out.push(s.slice(start, i)); start = i + 2; i++; }
  }
  if (s.length) out.push(s.slice(start));
  return out;
}

/**
 * One line of the trace, or null when it is not a syscall line. Only a line with runsc's log header
 * counts: a line without one is a continuation of a line before it (a path with a line break in
 * it), never a call. A call line whose argument list does not close gives { broken: true }.
 */
export function parseStraceLine(line) {
  const h = HEAD.exec(line);
  if (!h) return null;
  const t = TASK.exec(h[1]);
  if (!t) return null;
  const ids = /(\d+)\D+(\d+)/.exec(t[1]) || /(\d+)/.exec(t[1]);
  const c = CALL.exec(t[2]);
  if (!c) return null;
  const open = c[0].length;
  const close = argSpan(t[2], open);
  if (close < 0) return { broken: true, name: c[3] };
  const args = splitArgs(t[2].slice(open, close));
  const after = t[2].slice(close + 1);
  let ret = null;
  const m = /^\s*=\s*(.*)$/.exec(after);
  if (c[2] === 'X') {
    if (!m) return null;
    const v = /^(-?\d+|0x[0-9a-f]+)/i.exec(m[1]);
    const e = /errno=(\d+)(?: \(([^)]*)\))?/.exec(m[1]);
    ret = { value: v ? Number(v[1]) : null, errno: e ? Number(e[1]) : null, error: e && e[2] ? e[2].slice(0, 80) : null };
  }
  return { pid: ids ? Number(ids[1]) : null, tid: ids ? Number(ids[2] ?? ids[1]) : null, comm: c[1].trim().slice(0, 32), phase: c[2], name: c[3], args, ret };
}

/** A string as runsc prints it (Go %q) back to bytes. */
export function unquote(q) {
  const out = []; const s = String(q);
  const pushStr = (str) => out.push(...Buffer.from(str, 'utf8'));
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch !== '\\') { pushStr(ch); continue; }
    const n = s[++i];
    if (n === 'x') { out.push(parseInt(s.slice(i + 1, i + 3), 16) & 0xff); i += 2; } else if (n === 'u') { pushStr(String.fromCodePoint(parseInt(s.slice(i + 1, i + 5), 16))); i += 4; } else if (n === 'U') { pushStr(String.fromCodePoint(parseInt(s.slice(i + 1, i + 9), 16))); i += 8; } else pushStr({ a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', '"': '"', "'": "'" }[n] ?? n ?? '');
  }
  return Buffer.from(out);
}

/** The bytes of a dumped buffer argument (`0x7f.. "..."` or `0x7f.. "..."...`), or null. */
function blob(arg) {
  const m = /^0x[0-9a-f]+ "((?:[^"\\]|\\.)*)"/.exec(String(arg));
  return m ? unquote(m[1]) : null;
}

const cut = (s) => String(s).slice(0, STR_CAP);
/** A path argument: runsc prints a pointer then the path ("0x7f.. /etc/passwd"). */
function pathArg(a) {
  const m = /^0x[0-9a-f]+ (.*)$/.exec(String(a ?? ''));
  const p = m ? m[1] : String(a ?? '');
  return /^"(.*)"$/.test(p) ? unquote(p.slice(1, -1)).toString('utf8') : p;
}
/** A directory fd argument: "AT_FDCWD /cwd" or "0x3 /dir"; returns the directory or null. */
function dirArg(a) {
  const m = /^(?:AT_FDCWD|0x[0-9a-f]+) (\/.*)$/.exec(String(a ?? ''));
  return m ? m[1] : null;
}
function resolvePath(p, dir) {
  if (!p) return '';
  if (p.startsWith('/')) return posix.normalize(p);
  return dir ? posix.normalize(posix.join(dir, p)) : `./${posix.normalize(p)}`;
}
/** A sockaddr: {Family: AF_INET, Addr: 1.2.3.4, Port: 80} or {Family: AF_UNIX, Addr: "path"}. */
export function sockaddr(a) {
  const s = String(a ?? '');
  const f = /Family: ([A-Z0-9_]+)/.exec(s);
  if (!f) return null;
  const q = /Addr: "((?:[^"\\]|\\.)*)"/.exec(s);
  const addr = q ? unquote(q[1]).toString('utf8') : (/Addr: ([^,}]+)/.exec(s) || [])[1] ?? null;
  const port = /Port: (\d+)/.exec(s);
  return { family: f[1], addr: addr === null ? null : cut(addr.trim()), port: port ? Number(port[1]) : null };
}

const under = (p, list) => list.some((x) => (x.endsWith('/') ? p.startsWith(x) || p === x.slice(0, -1) : p === x));
const WRITE_FLAGS = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/;
const PATH_WRITES = { unlinkat: 1, unlink: 0, renameat2: 1, renameat: 1, rename: 0, mkdirat: 1, mkdir: 0, symlinkat: 2, symlink: 1, linkat: 3, link: 1, fchmodat: 1, chmod: 0, truncate: 0, mknodat: 1, mknod: 0, creat: 0 };

/**
 * A capped tally: key -> { ...fields, n, failed, errno (the last one) }. An entry with a call that
 * worked outranks one whose calls all failed, in the list and for a place in the table: when the
 * table is full, a call that worked takes the place of an all-failed entry, so a flood of refused
 * calls cannot push out the one that got through. `more_ok` counts worked calls left out anyway.
 */
class Tally {
  constructor(cap) { this.cap = cap; this.m = new Map(); this.more = 0; this.moreOk = 0; }
  add(key, fields, ret) {
    const failed = !!(ret && ret.errno !== null);
    let e = this.m.get(key);
    if (!e) {
      if (this.m.size >= this.cap * 4) {
        const victim = failed ? null : [...this.m.entries()].filter(([, x]) => x.failed === x.n).sort((a, b) => a[1].n - b[1].n)[0];
        if (!victim) { this.more++; if (!failed) this.moreOk++; return; }
        this.m.delete(victim[0]); this.more++;
      }
      e = { ...fields, n: 0, failed: 0, errno: null }; this.m.set(key, e);
    }
    e.n++;
    if (failed) { e.failed++; e.errno = ret.errno; }
  }
  list() {
    const worked = (x) => (x.failed < x.n ? 1 : 0);
    return [...this.m.values()].sort((a, b) => worked(b) - worked(a) || b.n - a.n || JSON.stringify(a).localeCompare(JSON.stringify(b))).slice(0, this.cap);
  }
  omitted() { return this.more + Math.max(0, this.m.size - this.cap); }
}

/** Builds the summary line by line; `cfg` is gvisor.json. */
export class TraceSummary {
  constructor(cfg, { cap = 40 } = {}) {
    this.cfg = cfg;
    this.cred = cfg.summary.credential.map((r) => new RegExp(r));
    this.lines = 0; this.parsed = 0; this.headerless = 0; this.headerlessBefore = 0; this.broken = 0;
    this.counts = Object.fromEntries([...FAMILIES, 'other'].map((f) => [f, 0]));
    this.failed = Object.fromEntries([...FAMILIES, 'other'].map((f) => [f, 0]));
    this.pending = new Map();
    this.opens = new Tally(cap); this.creds = new Tally(cap); this.execs = new Tally(cap);
    this.sockets = new Tally(cap); this.connects = new Tally(cap); this.sends = new Tally(cap); this.binds = new Tally(cap);
    this.priv = new Tally(cap); this.dns = new Tally(cap); this.links = new Tally(cap);
    this.clones = 0; this.cloneFailed = 0; this.rawSockets = 0;
  }

  add(line) {
    this.lines++;
    // runsc prints a block of its own without headers as the sandbox starts, before the first traced
    // call: only a headerless line after a call can be a target's doing.
    if (!HEAD.test(line)) { if (this.parsed || this.broken) this.headerless++; else this.headerlessBefore++; return; }
    const r = parseStraceLine(line);
    if (!r) return;
    if (r.broken) { this.broken++; return; }
    this.parsed++;
    const key = `${r.tid}:${r.name}`;
    if (r.phase === 'E') { this.pending.set(key, r); return; }
    this.pending.delete(key);
    this.call(r);
  }

  call(r) {
    const fam = syscallFamily(this.cfg, r.name);
    this.counts[fam]++;
    const ret = r.ret;
    if (ret && ret.errno !== null) this.failed[fam]++;
    const a = r.args; const sm = this.cfg.summary;
    const file = (path, op) => {
      const p = cut(path);
      if (this.cred.some((re) => re.test(p))) this.creds.add(`${op} ${p}`, { path: p, op }, ret);
      const ok = op === 'write' ? sm.write_ok : sm.read_ok;
      if (!under(p, ok)) this.opens.add(`${op} ${p}`, { path: p, op, call: r.name }, ret);
    };
    if (r.name === 'openat' || r.name === 'open') {
      const [p, fl] = r.name === 'openat' ? [resolvePath(pathArg(a[1]), dirArg(a[0])), a[2]] : [resolvePath(pathArg(a[0]), null), a[1]];
      file(p, WRITE_FLAGS.test(String(fl)) ? 'write' : 'read');
    } else if (r.name in PATH_WRITES) {
      const i = PATH_WRITES[r.name];
      const dir = i > 0 && /at2?$/.test(r.name) ? dirArg(a[i - 1]) : null;
      const p = resolvePath(pathArg(a[i]), dir);
      file(p, 'write');
      // A link the target made, and where it points: a symbolic link's target is kept as written
      // (it resolves when used), a hard link's source as a path (linkat: olddirfd, oldpath, newdirfd, newpath).
      if (r.name === 'symlinkat' || r.name === 'symlink') {
        const target = cut(pathArg(a[0]));
        this.links.add(`symlink ${target} ${cut(p)}`, { kind: 'symlink', target, path: cut(p) }, ret);
      } else if (r.name === 'linkat' || r.name === 'link') {
        const target = cut(r.name === 'linkat' ? resolvePath(pathArg(a[1]), dirArg(a[0])) : resolvePath(pathArg(a[0]), null));
        this.links.add(`hard ${target} ${cut(p)}`, { kind: 'hard', target, path: cut(p) }, ret);
      }
    } else if (r.name === 'execve' || r.name === 'execveat') {
      const p = r.name === 'execve' ? resolvePath(pathArg(a[0]), null) : resolvePath(pathArg(a[1]), dirArg(a[0]));
      this.execs.add(cut(p), { path: cut(p) }, ret);
    } else if (r.name === 'clone' || r.name === 'clone3' || r.name === 'fork' || r.name === 'vfork') {
      this.clones++; if (ret && ret.errno !== null) this.cloneFailed++;
    } else if (r.name === 'socket') {
      const family = cut(String(a[0] ?? '').split(' ')[0]); const type = cut(String(a[1] ?? '').split('|').filter((x) => !/CLOEXEC|NONBLOCK/.test(x)).join('|'));
      const raw = /SOCK_RAW|SOCK_PACKET/.test(type) || family === 'AF_PACKET';
      if (raw) this.rawSockets++;
      this.sockets.add(`${family} ${type} ${a[2]}`, { family, type, protocol: cut(a[2] ?? ''), raw }, ret);
    } else if (r.name === 'connect' || r.name === 'bind') {
      const sa = sockaddr(a[1]);
      if (sa) (r.name === 'connect' ? this.connects : this.binds).add(`${sa.family} ${sa.addr} ${sa.port}`, sa, ret);
    } else if (r.name === 'sendto') {
      const sa = sockaddr(a[4]);
      if (sa) this.sends.add(`${sa.family} ${sa.addr} ${sa.port}`, sa, ret);
      const b = blob(a[1]);
      const q = b && (!sa || sa.port === 53) ? parseQuestion(b) : null;
      if (q) this.dns.add(`${q.name} ${q.type}`, { name: q.name, type: q.type }, ret);
    } else if (fam === 'privileged') {
      this.priv.add(r.name, { name: r.name }, ret);
    }
  }

  result() {
    for (const r of this.pending.values()) this.call({ ...r, ret: null });
    this.pending.clear();
    const t = (x) => x.list();
    return {
      format: SUMMARY_FORMAT, target_influenced: true, lines: this.lines, syscalls: Object.values(this.counts).reduce((s, n) => s + n, 0),
      headerless_lines: this.headerless, headerless_before_calls: this.headerlessBefore, broken_lines: this.broken, injection_suspected: this.headerless > 0 || this.broken > 0,
      counts: this.counts, failed: this.failed,
      opens_outside: t(this.opens), credential_paths: t(this.creds), exec: t(this.execs),
      process: { clones: this.clones, clone_failed: this.cloneFailed },
      network: { sockets: t(this.sockets), raw_sockets: this.rawSockets, connects: t(this.connects), sends: t(this.sends), binds: t(this.binds), dns_names: t(this.dns) },
      privileged: t(this.priv), links: t(this.links),
      omitted: { opens_outside: this.opens.omitted(), credential_paths: this.creds.omitted(), exec: this.execs.omitted(), connects: this.connects.omitted(), sends: this.sends.omitted(), links: this.links.omitted() },
      // Calls that worked but found no place in a full table: a limit was hit where it matters.
      omitted_ok: { opens_outside: this.opens.moreOk, credential_paths: this.creds.moreOk, exec: this.execs.moreOk, connects: this.connects.moreOk, sends: this.sends.moreOk, sockets: this.sockets.moreOk },
    };
  }
}

/** The largest summary kept, as JSON: well under a telemetry record's 256 KiB. */
export const SUMMARY_MAX = 192 * 1024;
/** The lists a summary gives up first when it is too big; credential reads, programs run and connections last. */
const SHRINK_ORDER = [[null, 'opens_outside'], [null, 'links'], ['network', 'dns_names'], ['network', 'binds'], ['network', 'sends'], ['network', 'sockets'], [null, 'privileged'], ['network', 'connects'], [null, 'exec'], [null, 'credential_paths']];

/**
 * Cuts a summary down to `max` bytes of JSON by halving its lists, least telling first, and counts
 * what it cut in `omitted`. Paths and names a target chose can be mostly escaped bytes (six
 * characters each in JSON), so the size is measured, not assumed. Sets `shrunk` when it cut.
 */
export function fitSummary(s, max = SUMMARY_MAX) {
  let size = JSON.stringify(s).length;
  if (size <= max) return s;
  s.shrunk = true;
  for (const [parent, key] of SHRINK_ORDER) {
    const o = parent ? s[parent] : s;
    while (size > max && o && Array.isArray(o[key]) && o[key].length) {
      const keep = Math.floor(o[key].length / 2);
      s.omitted[key] = (s.omitted[key] ?? 0) + (o[key].length - keep);
      o[key] = o[key].slice(0, keep);
      size = JSON.stringify(s).length;
    }
  }
  return s;
}

export function summarizeTrace(text, cfg, opts) {
  const s = new TraceSummary(cfg, opts);
  for (const l of String(text).split('\n')) if (l) s.add(l);
  return fitSummary(s.result());
}

/** Streams a trace file (at most maxBytes of it) into a summary; null when the file cannot be read. */
export async function summarizeTraceFile(file, cfg, { maxBytes = 512 * 1024 * 1024, ...opts } = {}) {
  const s = new TraceSummary(cfg, opts);
  let bytes = 0;
  try {
    const rl = createInterface({ input: createReadStream(file, { end: maxBytes - 1 }), crlfDelay: Infinity });
    for await (const l of rl) { bytes += l.length + 1; if (l) s.add(l); }
  } catch { return null; }
  const r = s.result();
  r.bytes = bytes; r.truncated = bytes >= maxBytes;
  return fitSummary(r);
}
