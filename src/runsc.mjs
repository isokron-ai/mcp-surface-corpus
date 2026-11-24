// gVisor (runsc): the pinned config in gvisor.json, the runsc flags it gives, whether the Docker
// daemon has the runtime, and where runsc writes the syscall trace of one container.
// scripts/install-runsc.sh installs the bundle and registers `runsc` with exactly runscFlags().
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const GVISOR_FILE = fileURLToPath(new URL('../gvisor.json', import.meta.url));
export const RUNTIME = 'runsc';
export const FAMILIES = ['file', 'process', 'network', 'privileged'];
const NAME = /^[a-z][a-z0-9_]{1,31}$/;
const ARCHES = { x86_64: 'x86_64', amd64: 'x86_64', x64: 'x86_64', aarch64: 'aarch64', arm64: 'aarch64' };

export class RunscConfigError extends Error {}

/** Checks gvisor.json; throws on anything that would make the install or the flags ambiguous. */
export function validateRunscConfig(c) {
  const bad = (m) => { throw new RunscConfigError(`gvisor.json: ${m}`); };
  if (!c || typeof c !== 'object') bad('not an object');
  if (!/^\d{8}\.\d+$/.test(String(c.release))) bad('release must look like 20261116.0');
  if (c.runtime !== RUNTIME) bad(`runtime must be ${RUNTIME}`);
  for (const a of ['x86_64', 'aarch64']) {
    const b = c.bundles && c.bundles[a];
    if (!b || !/^[0-9a-f]{128}$/.test(String(b.sha512))) bad(`${a}: sha512 missing`);
    if (b.url !== `https://storage.googleapis.com/gvisor/releases/release/${c.release}/${a}/gvisor.tar.bz2`) bad(`${a}: the url is not the release's bundle`);
  }
  for (const k of ['install_dir', 'log_dir']) if (!/^\/[A-Za-z0-9/_.-]+$/.test(String(c[k])) || String(c[k]).includes('..')) bad(`${k} is not an absolute path`);
  if (!(Number.isInteger(c.trace_fs_mb) && c.trace_fs_mb >= 256 && c.trace_fs_mb <= 16384)) bad('trace_fs_mb must be 256 to 16384');
  if (!(Number.isInteger(c.trace_max_mb) && c.trace_max_mb >= 16 && c.trace_max_mb * 2 <= c.trace_fs_mb)) bad('trace_max_mb must be at least 16 and at most half of trace_fs_mb');
  if (!(Number.isInteger(c.volume_fs_mb) && c.volume_fs_mb >= 1024 && c.volume_fs_mb <= 65536)) bad('volume_fs_mb must be 1024 to 65536');
  if (!(Number.isInteger(c.volume_fs_inodes) && c.volume_fs_inodes >= 65536 && c.volume_fs_inodes <= 16777216)) bad('volume_fs_inodes must be 65536 to 16777216');
  const f = c.flags || {};
  if (f.network !== 'sandbox') bad('flags.network must be sandbox (gVisor\'s own network stack)');
  if (f['net-raw'] !== 'false') bad('flags.net-raw must be false');
  for (const [k, v] of Object.entries(f)) if (!/^[a-z][a-z0-9-]{1,40}$/.test(k) || !/^[A-Za-z0-9_.,:=/-]{1,80}$/.test(String(v))) bad(`flag ${k} is not plain`);
  for (const k of ['strace', 'strace-syscalls', 'strace-log-size', 'debug-log', 'debug', 'debug-log-fd']) if (k in f) bad(`flags.${k} is set from the strace block, not by hand`);
  const s = c.strace || {};
  if (!(Number.isInteger(s.log_size) && s.log_size >= 64 && s.log_size <= 4096)) bad('strace.log_size must be 64 to 4096');
  const seen = new Set();
  for (const fam of FAMILIES) {
    const list = s.families && s.families[fam];
    if (!Array.isArray(list) || !list.length) bad(`strace.families.${fam} is empty`);
    for (const n of list) { if (!NAME.test(n)) bad(`syscall name ${n}`); if (seen.has(n)) bad(`syscall ${n} is in two families`); seen.add(n); }
  }
  if (Object.keys(s.families).some((k) => !FAMILIES.includes(k))) bad('unknown syscall family');
  for (const n of s.amd64_only || []) if (!seen.has(n)) bad(`amd64_only names ${n}, which no family traces`);
  const sm = c.summary || {};
  for (const k of ['read_ok', 'write_ok']) if (!Array.isArray(sm[k]) || !sm[k].every((p) => typeof p === 'string' && p.startsWith('/'))) bad(`summary.${k}`);
  if (!Array.isArray(sm.credential)) bad('summary.credential');
  for (const r of sm.credential) { try { new RegExp(r); } catch { bad(`summary.credential: ${r}`); } }
  return c;
}

export function loadRunscConfig(file = GVISOR_FILE) {
  return validateRunscConfig(JSON.parse(readFileSync(file, 'utf8')));
}

export function normArch(a) {
  const n = ARCHES[String(a)];
  if (!n) throw new RunscConfigError(`no gVisor bundle for ${a}`);
  return n;
}

/** The traced syscalls on one architecture: every family, minus the names arm64 does not have. */
export function tracedSyscalls(c, arch) {
  const drop = normArch(arch) === 'aarch64' ? new Set(c.strace.amd64_only || []) : new Set();
  return FAMILIES.flatMap((f) => c.strace.families[f]).filter((n) => !drop.has(n));
}

export function syscallFamily(c, name) {
  for (const f of FAMILIES) if (c.strace.families[f].includes(name)) return f;
  return 'other';
}

/** The trace log of one container: runsc substitutes %ID% (the container id) and %COMMAND% (boot). */
export const debugLogPattern = (c) => `${c.log_dir}/%ID%.%COMMAND%.log`;
export function traceLogPath(c, containerId) {
  if (!/^[0-9a-f]{64}$/.test(String(containerId))) throw new RunscConfigError('not a container id');
  return join(c.log_dir, `${containerId}.boot.log`);
}

/** The runsc flags of the `runsc` Docker runtime (daemon.json runtimeArgs), in a fixed order. */
export function runscFlags(c, arch) {
  validateRunscConfig(c);
  return [
    ...Object.entries(c.flags).map(([k, v]) => `--${k}=${v}`),
    '--strace',
    `--strace-syscalls=${tracedSyscalls(c, arch).join(',')}`,
    `--strace-log-size=${c.strace.log_size}`,
    `--debug-log=${debugLogPattern(c)}`,
  ];
}

/**
 * Whether the daemon has the runtime, from `docker info --format '{{json .Runtimes}}'`. A missing
 * or unreadable answer is "no": the caller then skips, it never falls back to runc.
 */
export function runtimeAvailable(runtimesJson, name = RUNTIME) {
  try {
    const j = JSON.parse(String(runtimesJson));
    return !!(j && typeof j === 'object' && Object.prototype.hasOwnProperty.call(j, name));
  } catch { return false; }
}

/** The args the daemon actually has for the runtime (to record and to compare with runscFlags). */
export function runtimeArgs(runtimesJson, name = RUNTIME) {
  try {
    const r = JSON.parse(String(runtimesJson))[name];
    const a = r && (r.runtimeArgs || (r.options && r.options.Runtimeargs) || r.args);
    return Array.isArray(a) ? a.map(String) : [];
  } catch { return []; }
}
