// Docker plumbing for the driver: fixed `docker run` flags for the three kinds of container, and a
// process runner with a deadline and output caps. Patterns from isokron-ai/mcp-writecheck-action's
// corpus driver (same owner): digest-pinned images, user 10001, every capability dropped, a
// read-only root, named volumes only (never a host path, never the Docker socket), labels to sweep by.
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';

export class HarnessError extends Error {}

export const SANDBOX_USER = '10001:10001';
export const LABEL_RUN = 'isokron.surface.run';
export const LABEL_TARGET = 'isokron.surface.target';
/** Oldest Docker Engine accepted: before 26.0.0, --internal networks still resolved outside names (CVE-2024-29018). */
export const DOCKER_MIN = [26, 0, 0];
/** Limits of a container that runs target code (install, the server). */
export const LIMITS = { memory: '2g', pids: '512', cpus: 2, tmp: '512m' };

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

const labelArgs = (labels) => Object.entries(labels).flatMap(([k, v]) => ['--label', `${k}=${v}`]);
const envArgs = (env) => Object.entries(env).flatMap(([k, v]) => ['--env', `${k}=${v}`]);

/**
 * `docker run` arguments for a container that runs target code (the install, the server). Fixed
 * here and unit-tested; only the image, the network, the volumes, the env and the command vary.
 */
export function sandboxRunArgs({ name, image, network, mounts = [], env = {}, labels = {}, workdir = '/tmp', stdin = false, detach = false, cpus = LIMITS.cpus, cmd, entrypoint = null, aliases = [] }) {
  checkPinned(image, 'sandbox');
  if (typeof network !== 'string' || !network || network === 'host' || network === 'bridge' || network.startsWith('container:')) throw new HarnessError('a sandbox container never uses the host, default bridge or another container\'s network');
  return [
    'run', ...(detach ? ['--detach'] : ['--rm']), '--name', name, ...labelArgs(labels),
    '--user', SANDBOX_USER,
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--tmpfs', `/tmp:rw,nosuid,nodev,exec,size=${LIMITS.tmp},mode=1777`,
    '--pids-limit', LIMITS.pids,
    '--memory', LIMITS.memory, '--memory-swap', LIMITS.memory,
    '--cpus', String(cpus),
    '--ulimit', 'nofile=4096:4096',
    '--init',
    '--hostname', 'surface',
    '--network', network, ...aliases.flatMap((a) => ['--network-alias', a]),
    '--workdir', workdir,
    ...mounts.flatMap((m) => ['--mount', volumeMount(m)]),
    ...envArgs(env),
    ...(stdin ? ['--interactive'] : []),
    ...(entrypoint ? ['--entrypoint', entrypoint] : []),
    image, ...cmd,
  ];
}

/**
 * Our own code in a container (the static reader, the analyser, the HTTP probe, the egress proxy, a
 * file copy): never target code, but it reads target data, so it is boxed the same way. No network
 * unless one is named.
 */
export function helperRunArgs({ name, image, network = 'none', mounts = [], env = {}, labels = {}, stdin = false, detach = false, memory = '2g', cpus = 1, cmd, user = SANDBOX_USER, capAdd = [] }) {
  checkPinned(image, 'helper');
  if (!capAdd.every((c) => c === 'CHOWN')) throw new HarnessError('a helper may be given CHOWN only');
  return [
    'run', ...(detach ? ['--detach'] : ['--rm']), '--name', name, ...labelArgs(labels),
    '--user', user, '--cap-drop', 'ALL', ...capAdd.flatMap((c) => ['--cap-add', c]), '--security-opt', 'no-new-privileges', '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
    '--pids-limit', '256', '--memory', memory, '--memory-swap', memory, '--cpus', String(cpus), '--init',
    '--network', network,
    ...mounts.flatMap((m) => ['--mount', volumeMount(m)]),
    ...envArgs(env),
    ...(stdin ? ['--interactive'] : []),
    image, ...cmd,
  ];
}

/**
 * Runs a command with a deadline. stdout is kept (up to `cap` bytes) when keepStdout is set; stdout
 * and stderr also go to `log` (bounded) unless logStdout is false. Returns
 * { exit, signal, timed_out, stdout, stdout_bytes, stdout_truncated, ms }.
 */
export function run(cmd, argv, { env, log = null, deadline = null, input = null, keepStdout = false, logStdout = true, cap = 64 * 1024 * 1024, logCap = 16 * 1024 * 1024, onTimeout = null } = {}) {
  return new Promise((done) => {
    const t0 = Date.now();
    let child;
    try { child = spawn(cmd, argv, { env, stdio: ['pipe', 'pipe', 'pipe'] }); } catch (e) { return done({ exit: 127, signal: null, timed_out: false, stdout: Buffer.alloc(0), stdout_bytes: 0, stdout_truncated: false, ms: 0, spawn_error: e.message }); }
    const chunks = []; let kept = 0; let total = 0; let logged = 0; let truncated = false; let timedOut = false; let timer = null;
    const toLog = (c) => { if (!log || logged >= logCap) return; const b = c.subarray(0, logCap - logged); logged += b.length; try { appendFileSync(log, b); } catch { /* the log is best effort */ } };
    child.stdout.on('data', (c) => {
      total += c.length;
      if (keepStdout) { if (kept + c.length <= cap) { chunks.push(c); kept += c.length; } else truncated = true; }
      if (logStdout) toLog(c);
    });
    child.stderr.on('data', toLog);
    child.stdin.on('error', () => {});
    child.on('error', (e) => { clearTimeout(timer); done({ exit: 127, signal: null, timed_out: false, stdout: Buffer.alloc(0), stdout_bytes: 0, stdout_truncated: false, ms: Date.now() - t0, spawn_error: e.message }); });
    child.on('close', (code, signal) => { clearTimeout(timer); done({ exit: code, signal, timed_out: timedOut, stdout: Buffer.concat(chunks), stdout_bytes: total, stdout_truncated: truncated, ms: Date.now() - t0 }); });
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
    this.n = 0;
  }

  labels(target = null) { return { [LABEL_RUN]: this.runId, ...(target ? { [LABEL_TARGET]: target } : {}) }; }
  name(target, what) { return `surface-${this.runId}-${target ?? 'shard'}-${what}${++this.n}`; }
  d(argv, opts = {}) { return run('docker', argv, { env: this.env, log: this.log, ...opts }); }

  async must(p, what) {
    const r = await p;
    if (r.exit !== 0) throw new HarnessError(`${what} failed (exit ${r.exit}${r.timed_out ? ', time limit' : ''})`);
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

  async network(name, internal, target = null) {
    await this.must(this.d(['network', 'create', ...(internal ? ['--internal'] : []), '--driver', 'bridge', ...labelArgs(this.labels(target)), name]), 'network create');
    const r = await this.d(['network', 'inspect', '--format', '{{.Internal}}', name], { keepStdout: true, logStdout: false });
    if ((r.stdout.toString().trim() === 'true') !== internal) throw new HarnessError(`the network ${internal ? 'is not internal' : 'is internal'}`);
    return name;
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
