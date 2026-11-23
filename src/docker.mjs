// Container plumbing for the driver: fixed `run` flags for the three kinds of container, and a
// process runner with a deadline and output caps. Patterns from isokron-ai/mcp-writecheck-action's
// corpus driver (same owner): digest-pinned images, every capability dropped, a read-only root,
// named volumes only (never a host path, never the daemon socket), labels to sweep by. Every
// container runs under gVisor (`--runtime runsc`, src/runsc.mjs) as user 65534 (nobody); the one
// file mounted from the host is our read-only resolv.conf on a sandbox network (src/sandbox-net.mjs).
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { RUNTIME } from './runsc.mjs';
import { NETS, SANDBOX_RANGE } from './sandbox-net.mjs';
import { targetEnvProblems } from './sandbox-env.mjs';

export class HarnessError extends Error {}

export const SANDBOX_USER = '65534:65534';
export const LABEL_RUN = 'isokron.surface.run';
export const LABEL_TARGET = 'isokron.surface.target';
/** Oldest Docker Engine accepted: before 26.0.0, --internal networks still resolved outside names (CVE-2024-29018). */
export const DOCKER_MIN = [26, 0, 0];
/**
 * Limits of a container that runs target code (install, the server). The process limit a target
 * meets is `nproc`: gVisor's kernel counts the processes and threads inside the sandbox and refuses
 * a fork past RLIMIT_NPROC with EAGAIN (it does not apply the OCI pids limit inside). `pids` is the
 * host cgroup's limit on the sandbox's own host tasks: gVisor's threads plus, on its default
 * platform, a host stub process and thread for each sandboxed process. It is a backstop sized above
 * what `nproc` lets a target make (about two host tasks each), so a fork bomb meets EAGAIN inside
 * the sandbox instead of crashing it at the host limit.
 */
export const LIMITS = { memory: '2g', pids: '2048', nproc: '512', cpus: 2, tmp: '512m' };

const PINNED = /^[a-z0-9][a-z0-9./_-]{0,200}(?::[A-Za-z0-9._-]{1,120})?@sha256:[0-9a-f]{64}$/;
export function checkPinned(ref, what = 'image') {
  if (typeof ref !== 'string' || !PINNED.test(ref)) throw new HarnessError(`the ${what} image is not pinned by digest`);
  return ref;
}

export function checkDockerVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v));
  if (!m) throw new HarnessError('the Docker Engine version could not be read');
  const got = m.slice(1).map(Number);
  for (let i = 0; i < 3; i++) { if (got[i] > DOCKER_MIN[i]) return; if (got[i] < DOCKER_MIN[i]) throw new HarnessError(`Docker Engine ${DOCKER_MIN.join('.')} or later is needed`); }
}

/**
 * The environment of the docker client processes the driver starts: what docker needs to find its
 * daemon, nothing else. No GITHUB_*, ACTIONS_*, RUNNER_*, no token, no key.
 */
export function dockerEnvFrom(env) {
  const keep = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'];
  return Object.fromEntries(keep.filter((k) => env[k] !== undefined).map((k) => [k, env[k]]));
}

/** Only named Docker volumes, by a name the driver made; never a host path. */
export function volumeMount({ src, dst, ro = false }) {
  if (!/^surface-[a-z0-9-]+$/.test(src)) throw new HarnessError('only surface volumes are mounted');
  if (!/^\/[A-Za-z0-9._/-]+$/.test(dst)) throw new HarnessError('bad mount path');
  return `type=volume,src=${src},dst=${dst}${ro ? ',readonly' : ''}`;
}

/** The one host file a container may see: our resolv.conf of a sandbox network, read-only (net-guard.sh writes it). */
export function resolvMount(net, network) {
  if (!Object.prototype.hasOwnProperty.call(NETS, String(net))) throw new HarnessError('resolv: only a sandbox network\'s resolv.conf is mounted');
  if (network === 'none') throw new HarnessError('resolv: no resolv.conf where there is no network');
  return `type=bind,src=${NETS[net].resolv},dst=/etc/resolv.conf,readonly`;
}

const [RANGE_NET, RANGE_BITS] = SANDBOX_RANGE.split('/');
const ip4 = (s) => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);
/** A fixed address, only inside the sandbox range and only on a named network. */
export function checkSandboxIp(ip, network) {
  const ok = typeof ip === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every((o) => Number(o) <= 255)
    && Math.floor(ip4(ip) / 2 ** (32 - Number(RANGE_BITS))) === Math.floor(ip4(RANGE_NET) / 2 ** (32 - Number(RANGE_BITS)));
  if (!ok || network === 'none') throw new HarnessError(`the address ${String(ip).slice(0, 40)} is not one of the sandbox networks'`);
  return ip;
}

const labelArgs = (labels) => Object.entries(labels).flatMap(([k, v]) => ['--label', `${k}=${v}`]);
const envArgs = (env) => Object.entries(env).flatMap(([k, v]) => ['--env', `${k}=${v}`]);
const netArgs = ({ network, ip, resolv, cidfile }) => {
  if (cidfile !== null && !/^\/[A-Za-z0-9._/-]{1,300}$/.test(String(cidfile))) throw new HarnessError('the cidfile must be an absolute path');
  return [
    ...(ip !== null ? ['--ip', checkSandboxIp(ip, network)] : []),
    ...(resolv !== null ? ['--mount', resolvMount(resolv, network)] : []),
    ...(cidfile !== null ? ['--cidfile', cidfile] : []),
  ];
};

/**
 * `docker run` arguments for a container that runs target code (the install, the server). Fixed
 * here and unit-tested; only the image, the network (with its address and resolv.conf), the
 * volumes, the env and the command vary. The runtime is always gVisor: there is no option for it.
 */
export function sandboxRunArgs({ name, image, network, mounts = [], env = {}, labels = {}, workdir = '/tmp', stdin = false, detach = false, cpus = LIMITS.cpus, cmd, entrypoint = null, aliases = [], ip = null, resolv = null, cidfile = null, hostEnv = process.env }) {
  checkPinned(image, 'sandbox');
  if (typeof network !== 'string' || !network || network === 'host' || network === 'bridge' || network.startsWith('container:')) throw new HarnessError('a sandbox container never uses the host, default bridge or another container\'s network');
  const bad = targetEnvProblems(env, hostEnv);
  if (bad.length) throw new HarnessError(`the target environment is refused: ${bad.join('; ').slice(0, 300)}`);
  return [
    'run', ...(detach ? ['--detach'] : ['--rm']), '--name', name, ...labelArgs(labels),
    '--runtime', RUNTIME,
    '--user', SANDBOX_USER,
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--tmpfs', `/tmp:rw,nosuid,nodev,exec,size=${LIMITS.tmp},mode=1777`,
    '--pids-limit', LIMITS.pids,
    '--memory', LIMITS.memory, '--memory-swap', LIMITS.memory,
    '--cpus', String(cpus),
    '--ulimit', 'nofile=4096:4096',
    '--ulimit', `nproc=${LIMITS.nproc}:${LIMITS.nproc}`,
    '--init',
    '--hostname', 'surface',
    '--network', network, ...aliases.flatMap((a) => ['--network-alias', a]),
    ...netArgs({ network, ip, resolv, cidfile }),
    '--workdir', workdir,
    ...mounts.flatMap((m) => ['--mount', volumeMount(m)]),
    ...envArgs(env),
    ...(stdin ? ['--interactive'] : []),
    ...(entrypoint ? ['--entrypoint', entrypoint] : []),
    image, ...cmd,
  ];
}

/** `--add-host` entries: a one-label name (it cannot stand in for a real host) for a sandbox address. */
const hostArgs = (hosts, network) => hosts.flatMap(([n, ip]) => {
  if (!/^[a-z][a-z0-9-]{0,30}$/.test(String(n))) throw new HarnessError('a fixed host entry takes a one-label host name');
  return ['--add-host', `${n}:${checkSandboxIp(ip, network)}`];
});

/** Runtimes a helper may name: gVisor, or runc for the egress proxy alone (it resolves registry names through the daemon's DNS, which gVisor's own network stack does not reach). */
const HELPER_RUNTIMES = [RUNTIME, 'runc'];

/**
 * Our own code in a container (the static reader, the analyser, the HTTP probe, the network logger,
 * the egress proxy, a file copy): never target code, but it reads target data, so it is boxed the
 * same way and runs under gVisor too. No network unless one is named.
 */
export function helperRunArgs({ name, image, network = 'none', mounts = [], env = {}, labels = {}, stdin = false, detach = false, memory = '2g', cpus = 1, cmd, user = SANDBOX_USER, capAdd = [], runtime = RUNTIME, ip = null, resolv = null, cidfile = null, hosts = [] }) {
  checkPinned(image, 'helper');
  if (!capAdd.every((c) => c === 'CHOWN' || c === 'NET_BIND_SERVICE')) throw new HarnessError('a helper may be given CHOWN or NET_BIND_SERVICE only');
  if (!HELPER_RUNTIMES.includes(runtime)) throw new HarnessError(`a helper runs under ${HELPER_RUNTIMES.join(' or ')}, not the runtime ${String(runtime).slice(0, 40)}`);
  return [
    'run', ...(detach ? ['--detach'] : ['--rm']), '--name', name, ...labelArgs(labels),
    '--runtime', runtime,
    '--user', user, '--cap-drop', 'ALL', ...capAdd.flatMap((c) => ['--cap-add', c]), '--security-opt', 'no-new-privileges', '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
    '--pids-limit', '256', '--memory', memory, '--memory-swap', memory, '--cpus', String(cpus), '--init',
    '--network', network,
    ...netArgs({ network, ip, resolv, cidfile }),
    ...hostArgs(hosts, network),
    ...mounts.flatMap((m) => ['--mount', volumeMount(m)]),
    ...envArgs(env),
    ...(stdin ? ['--interactive'] : []),
    image, ...cmd,
  ];
}

/**
 * Runs a command with a deadline. stdout is kept (up to `cap` bytes) when keepStdout is set; stdout
 * and stderr also go to `log` (bounded) unless logStdout is false. The last STDERR_TAIL bytes of
 * stderr are always kept, so a failed harness step can say why (HarnessError, Docker.must). Returns
 * { exit, signal, timed_out, stdout, stdout_bytes, stdout_truncated, stderr_tail, ms }.
 */
export const STDERR_TAIL = 2048;

/** stderr as one bounded line for an error message: printable ASCII only, line breaks shown as ' | '. */
export function tailLine(buf, max = 400) {
  const t = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf ?? '');
  const line = t.replace(/\r?\n+/g, ' | ').replace(/[^\x20-\x7e]/g, '?').replace(/\s+/g, ' ').replace(/^[ |]+|[ |]+$/g, '');
  return line.length > max ? `...${line.slice(-max)}` : line;
}

export function run(cmd, argv, { env, log = null, deadline = null, input = null, keepStdout = false, logStdout = true, cap = 64 * 1024 * 1024, logCap = 16 * 1024 * 1024, onTimeout = null } = {}) {
  return new Promise((done) => {
    const t0 = Date.now();
    let child;
    try { child = spawn(cmd, argv, { env, stdio: ['pipe', 'pipe', 'pipe'] }); } catch (e) { return done({ exit: 127, signal: null, timed_out: false, stdout: Buffer.alloc(0), stdout_bytes: 0, stdout_truncated: false, stderr_tail: Buffer.alloc(0), ms: 0, spawn_error: e.message }); }
    const chunks = []; let kept = 0; let total = 0; let logged = 0; let truncated = false; let timedOut = false; let timer = null;
    const toLog = (c) => { if (!log || logged >= logCap) return; const b = c.subarray(0, logCap - logged); logged += b.length; try { appendFileSync(log, b); } catch { /* the log is best effort */ } };
    child.stdout.on('data', (c) => {
      total += c.length;
      if (keepStdout) { if (kept + c.length <= cap) { chunks.push(c); kept += c.length; } else truncated = true; }
      if (logStdout) toLog(c);
    });
    let errTail = Buffer.alloc(0);
    child.stderr.on('data', (c) => {
      errTail = Buffer.concat([errTail, c]);
      if (errTail.length > STDERR_TAIL) errTail = errTail.subarray(errTail.length - STDERR_TAIL);
      toLog(c);
    });
    child.stdin.on('error', () => {});
    child.on('error', (e) => { clearTimeout(timer); done({ exit: 127, signal: null, timed_out: false, stdout: Buffer.alloc(0), stdout_bytes: 0, stdout_truncated: false, stderr_tail: errTail, ms: Date.now() - t0, spawn_error: e.message }); });
    child.on('close', (code, signal) => { clearTimeout(timer); done({ exit: code, signal, timed_out: timedOut, stdout: Buffer.concat(chunks), stdout_bytes: total, stdout_truncated: truncated, stderr_tail: errTail, ms: Date.now() - t0 }); });
    if (deadline !== null) {
      timer = setTimeout(async () => {
        timedOut = true;
        try { if (onTimeout) await onTimeout(); } catch { /* the kill below still runs */ }
        try { child.kill('SIGKILL'); } catch { /* gone */ }
      }, Math.max(0, deadline - Date.now()));
    }
    if (input !== null) child.stdin.end(input); else child.stdin.end();
  });
}

/** One shard's Docker session: every object it makes carries the run label, so one sweep removes all. */
export class Docker {
  constructor({ runId, env = process.env, log = null }) {
    this.runId = runId;
    this.env = dockerEnvFrom(env);
    this.log = log;
    // In an object, so a per-target view (Object.create(session) with its own log) shares it.
    this.counter = { n: 0 };
  }

  labels(target = null) { return { [LABEL_RUN]: this.runId, ...(target ? { [LABEL_TARGET]: target } : {}) }; }
  name(target, what) { return `surface-${this.runId}-${target ?? 'shard'}-${what}${++this.counter.n}`; }
  d(argv, opts = {}) { return run('docker', argv, { env: this.env, log: this.log, ...opts }); }

  /**
   * A harness step that must succeed. Only our own commands go through here (docker itself and our
   * helper containers, never a container that runs target code), so the failure carries the tail of
   * their stderr: that is how a step that fails on a runner says why.
   */
  async must(p, what) {
    const r = await p;
    if (r.exit !== 0) {
      const why = tailLine(r.stderr_tail || r.spawn_error || '');
      throw new HarnessError(`${what} failed (exit ${r.exit}${r.timed_out ? ', time limit' : ''})${why ? `: ${why}` : ''}`);
    }
    return r;
  }

  /** A digest-pinned image, pulled only when it is not here already. Returns the local image id. */
  async image(ref, what) {
    checkPinned(ref, what);
    let id = await this.d(['image', 'inspect', '--format', '{{.Id}}', ref], { keepStdout: true, logStdout: false });
    if (id.exit !== 0) {
      await this.must(this.d(['pull', '-q', ref], { deadline: Date.now() + 600_000 }), `${what} pull`);
      id = await this.must(this.d(['image', 'inspect', '--format', '{{.Id}}', ref], { keepStdout: true, logStdout: false }), `${what} inspect`);
    }
    return id.stdout.toString().trim();
  }

  /** A new, empty volume; one that exists already is refused. */
  async volume(name, target = null) {
    const seen = await this.d(['volume', 'inspect', '--format', '{{.Name}}', name], { keepStdout: true, logStdout: false });
    if (seen.exit === 0) throw new HarnessError('a volume of that name exists already');
    await this.must(this.d(['volume', 'create', ...labelArgs(this.labels(target)), name]), 'volume create');
    return name;
  }

  /**
   * A new bridge network. `sandbox` names one of the fixed sandbox networks (src/sandbox-net.mjs):
   * internal, its fixed subnet and gateway, no IPv6, and checked to be exactly that after creation.
   */
  async network(name, internal, target = null, { sandbox = null } = {}) {
    const sn = sandbox === null ? null : NETS[sandbox];
    if (sandbox !== null && (!sn || !internal)) throw new HarnessError('a sandbox network is one of the fixed ones, and internal');
    const fixed = sn ? ['--subnet', sn.subnet, '--gateway', sn.gateway, '--ipv6=false', '--opt', 'com.docker.network.bridge.enable_ip_masquerade=false'] : [];
    await this.must(this.d(['network', 'create', ...(internal ? ['--internal'] : []), '--driver', 'bridge', ...fixed, ...labelArgs(this.labels(target)), name]), 'network create');
    const r = await this.d(['network', 'inspect', '--format', '{{.Internal}} {{.EnableIPv6}} {{range .IPAM.Config}}{{.Subnet}}{{end}}', name], { keepStdout: true, logStdout: false });
    const [isInternal, v6, subnet] = r.stdout.toString().trim().split(' ');
    if ((isInternal === 'true') !== internal) throw new HarnessError(`the network ${internal ? 'is not internal' : 'is internal'}`);
    if (sn && (v6 !== 'false' || subnet !== sn.subnet)) throw new HarnessError('the sandbox network does not have its fixed subnet, or has IPv6');
    return name;
  }

  /** The daemon's runtimes as JSON (`docker info`), or '' when it cannot be read. */
  async runtimes() {
    const r = await this.d(['info', '--format', '{{json .Runtimes}}'], { keepStdout: true, logStdout: false, deadline: Date.now() + 30_000 });
    return r.exit === 0 ? r.stdout.toString().trim() : '';
  }

  /** Kills a container and with it every process in it (its pid namespace ends). */
  async kill(name) { await this.d(['rm', '-f', '-v', name], { deadline: Date.now() + 30_000 }); }

  /** Remove everything this shard (or one target) created: containers, then networks and volumes. */
  async sweep(target = null) {
    const f = ['--filter', `label=${LABEL_RUN}=${this.runId}`, ...(target ? ['--filter', `label=${LABEL_TARGET}=${target}`] : [])];
    const list = async (argv) => (await this.d(argv, { keepStdout: true, logStdout: false })).stdout.toString().split('\n').filter(Boolean);
    const ids = await list(['ps', '-aq', ...f]);
    if (ids.length) await this.d(['rm', '-f', '-v', ...ids]);
    const nets = await list(['network', 'ls', '-q', ...f]);
    if (nets.length) await this.d(['network', 'rm', ...nets]);
    const vols = await list(['volume', 'ls', '-q', ...f]);
    if (vols.length) await this.d(['volume', 'rm', '-f', ...vols]);
  }
}
