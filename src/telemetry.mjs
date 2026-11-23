// Run telemetry: one JSON object per line, written by the harness only. docs/TELEMETRY.md is the
// schema; validateRecord() is the same schema as code, and every record is checked before it is
// written. Sources: the harness itself, the network logger (DNS and sinkhole), the egress proxy,
// runsc's syscall trace, and the host firewall's log. A target's own output is never a record:
// at most its size and hash are (`target_output`).
import { appendFileSync, readFileSync } from 'node:fs';

export const TELEMETRY_VERSION = 1;
export const SOURCES = ['harness', 'netlog', 'proxy', 'runsc', 'host'];
export const ROLES = ['install', 'server', 'probe', 'netlog', 'proxy', 'helper', 'baseline', 'smoke', 'case'];
export const SKIP_REASONS = ['runtime_unavailable', 'sandbox_setup_missing', 'network_setup_failed', 'trace_unavailable', 'host_log_unavailable', 'disabled'];

const str = (max = 300) => (v) => typeof v === 'string' && v.length <= max;
const strOrNull = (max = 300) => (v) => v === null || (typeof v === 'string' && v.length <= max);
const int = (v) => Number.isInteger(v) && v >= 0;
const intOrNull = (v) => v === null || Number.isInteger(v);
const bool = (v) => typeof v === 'boolean';
const boolOrNull = (v) => v === null || typeof v === 'boolean';
const obj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const arr = (v) => Array.isArray(v);
const oneOf = (l) => (v) => l.includes(v);
const hex64 = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const ip = (v) => typeof v === 'string' && v.length <= 64 && /^[0-9a-fA-F:.]+$/.test(v);
const ipOrNull = (v) => v === null || ip(v);
const port = (v) => v === null || (Number.isInteger(v) && v >= 0 && v <= 65535);
/** A port from a container's output: an integer 0 to 65535, anything else null. */
export const clampPort = (v) => (Number.isInteger(v) && v >= 0 && v <= 65535 ? v : null);
/** A count from a container's output: a whole number, anything else 0. */
const count = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
export const MAX_RECORD = 256 * 1024;

/** Required fields per record type (optional fields are listed in docs/TELEMETRY.md). */
export const TYPES = {
  run_start: { kind: oneOf(['corpus', 'selftest']), lane: str(20), node: str(40), platform: str(40), runtime: str(20), gvisor_release: str(40) },
  runtime: { available: bool, name: str(20), release: str(40), flags_expected: arr, flags_daemon: arr, flags_match: bool, smoke: oneOf(['ok', 'failed', 'not_run']) },
  skip: { reason: oneOf(SKIP_REASONS), detail: str(300) },
  settings: { digest: hex64, manifest: obj },
  container: { runtime: str(20), exit: intOrNull, signal: strOrNull(20), timed_out: bool, oom_killed: boolOrNull, ms: int },
  dns_query: { from: ipOrNull, proto: oneOf(['udp', 'tcp']), qname: str(253), qtype: str(10), answer: oneOf(['sinkhole', 'empty', 'nxdomain', 'refused', 'formerr']) },
  connection: { from: ipOrNull, proto: oneOf(['tcp', 'udp']), port, bytes: int },
  egress: { host: str(260), port, allowed: bool },
  host_drop: { chain: oneOf(['forward', 'input', 'forward6', 'input6']), family: oneOf([4, 6]), proto: str(12), src: ipOrNull, dst: ipOrNull, dpt: port },
  trace_summary: { summary: obj },
  target_output: { stream: oneOf(['stdout', 'stderr', 'file']), bytes: int, sha256: hex64, untrusted: (v) => v === true },
  case_evidence: { case: str(40), canary_hits: intOrNull, inspect: obj, telemetry_has_nonce: boolOrNull, pids_limit: int },
  bypass_result: { case: str(40), blocked: bool, logged: bool, pass: bool, evidence: arr, detail: str(600) },
  run_end: { records: int, skipped: int, ok: bool },
};

/** Problems with one record; an empty list when it matches the schema. */
export function validateRecord(r) {
  const errs = [];
  if (!obj(r)) return ['not an object'];
  if (r.v !== TELEMETRY_VERSION) errs.push('v');
  if (!Object.prototype.hasOwnProperty.call(TYPES, r.type)) return [...errs, `type ${r.type}`];
  if (!/^[0-9a-z-]{4,40}$/.test(String(r.run))) errs.push('run');
  if (!int(r.seq)) errs.push('seq');
  if (typeof r.t !== 'string' || Number.isNaN(Date.parse(r.t))) errs.push('t');
  if (!SOURCES.includes(r.source)) errs.push('source');
  if (!(r.subject === null || (typeof r.subject === 'string' && /^[a-z0-9:_-]{1,48}$/.test(r.subject)))) errs.push('subject');
  if (!(r.role === null || ROLES.includes(r.role))) errs.push('role');
  for (const [k, ok] of Object.entries(TYPES[r.type])) if (!ok(r[k])) errs.push(`${r.type}.${k}`);
  if (JSON.stringify(r).length > MAX_RECORD) errs.push('record over 256 KiB');
  return errs;
}

export class TelemetryError extends Error {}

/** Appends records to one JSON Lines file. */
export class Telemetry {
  constructor(file, { run, clock = () => new Date() }) {
    this.file = file; this.run = run; this.clock = clock; this.seq = 0; this.counts = {}; this.dropped = 0; this.droppedBy = {};
  }

  /**
   * write() for a record that carries data a container produced (its network lines, its trace, its
   * proxy requests): a record the schema refuses is dropped and counted, never thrown, so one bad
   * line cannot end the run or take the records after it with it. run_end reports the count.
   */
  tryWrite(type, fields = {}, meta = {}) {
    try { return this.write(type, fields, meta); } catch (e) {
      if (!(e instanceof TelemetryError)) throw e;
      this.dropped++; this.droppedBy[type] = (this.droppedBy[type] ?? 0) + 1;
      return null;
    }
  }

  write(type, fields = {}, { source = 'harness', subject = null, role = null } = {}) {
    const r = { v: TELEMETRY_VERSION, type, run: this.run, seq: this.seq, t: this.clock().toISOString(), source, subject, role, ...fields };
    const errs = validateRecord(r);
    if (errs.length) throw new TelemetryError(`telemetry record ${type}: ${errs.join(', ')}`);
    appendFileSync(this.file, `${JSON.stringify(r)}\n`);
    this.seq++;
    this.counts[type] = (this.counts[type] ?? 0) + 1;
    return r;
  }

  end(ok) { return this.write('run_end', { records: this.seq + 1, skipped: this.counts.skip ?? 0, ok, telemetry_dropped: this.dropped }); }
}

/** Reads a telemetry file back; lines that are not valid records are reported, not dropped silently. */
export function readTelemetry(file) {
  const records = []; const bad = [];
  readFileSync(file, 'utf8').split('\n').forEach((l, i) => {
    if (!l) return;
    let r = null; try { r = JSON.parse(l); } catch { /* reported below */ }
    const e = r ? validateRecord(r) : ['not JSON'];
    if (e.length) bad.push({ line: i + 1, errors: e }); else records.push(r);
  });
  return { records, bad };
}

/** A new run id: the UTC time to the second and a random suffix, lower case (`20261121t100000-3f9a1c`). */
export function newRunId(now = new Date(), rand = Math.random) {
  const t = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, '').toLowerCase();
  return `${t}-${Math.floor(rand() * 0xffffff).toString(16).padStart(6, '0')}`;
}

/** A grouped host firewall drop (src/sandbox-net.mjs groupDrops) as a record. */
export function fromDrop(d) {
  const f = { chain: d.chain, family: d.family, proto: String(d.proto).slice(0, 12), src: d.src ?? null, dst: d.dst ?? null, dpt: clampPort(d.dpt), n: Number.isInteger(d.n) && d.n >= 0 ? d.n : 1 };
  if (Number.isInteger(d.icmp_type)) f.icmp_type = d.icmp_type;
  return ['host_drop', f];
}

/** A network logger line (sandbox/netlog.mjs) as a record type and fields, or null. */
export function fromNetlog(o) {
  if (!obj(o)) return null;
  if (o.kind === 'dns') return ['dns_query', { from: o.from ?? null, proto: o.proto, qname: String(o.qname).slice(0, 253), qtype: String(o.qtype).slice(0, 10), answer: o.answer }];
  if (o.kind === 'conn') {
    const f = { from: o.from ?? null, proto: o.proto, port: clampPort(o.port), bytes: count(o.bytes) };
    if (typeof o.sni === 'string') f.sni = o.sni.slice(0, 253);
    if (obj(o.http)) f.http = { method: String(o.http.method).slice(0, 16), host: String(o.http.host ?? '').slice(0, 253), path: String(o.http.path ?? '').slice(0, 200) };
    if (typeof o.first_hex === 'string') f.first_hex = o.first_hex.slice(0, 64);
    return ['connection', f];
  }
  return null;
}

/** An egress proxy line (sandbox/egress-proxy.mjs) as a record, or null (its "listening" line). */
export function fromProxy(o) {
  if (!obj(o) || typeof o.allowed !== 'boolean') return null;
  const f = { host: String(o.host ?? '').slice(0, 260), port: clampPort(o.port), allowed: o.allowed };
  for (const k of ['up', 'down', 'ms']) if (Number.isInteger(o[k]) && o[k] >= 0) f[k] = o[k];
  if (typeof o.error === 'string') f.error = o.error.slice(0, 80);
  if (typeof o.method === 'string') f.method = o.method.slice(0, 16);
  return ['egress', f];
}
