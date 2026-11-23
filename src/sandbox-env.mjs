// The environment and settings of a container that runs target code. A target never inherits the
// runner's environment: the docker client passes only the names the harness sets, and this module
// refuses runner, Actions and token names outright, and any value the host holds under a secret
// name (so a token cannot reach a container under a harmless name either). The settings manifest is
// read back from the exact `docker run` arguments the harness used, so what is recorded is what ran;
// its digest goes into the run telemetry, and the self test compares it with `docker inspect`.
import { createHash } from 'node:crypto';

/** Names a target container never gets, whatever the value: the runner's and Actions' own, tokens, loader hooks. */
export const ENV_DENY = /^(?:GITHUB_|ACTIONS_|RUNNER_|INPUT_|STATE_|CORPUS_|DOCKER_|GH_|GIT_|SSH_|LD_|BASH_ENV$|ENV$|SURFACE_(?!SANDBOX$))/i;
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** Host variables whose values are secrets: no target value may contain one. */
const SECRET_HOST_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|_KEY$|^KEY$|^GH_|^ACTIONS_ID_TOKEN|^ACTIONS_RUNTIME|^ACTIONS_CACHE|^ACTIONS_RESULTS)/i;

export const envNameAllowed = (n) => typeof n === 'string' && NAME.test(n) && !ENV_DENY.test(n);

/** The values (8 characters or more) of the host's secret-named variables. */
export function hostSecretValues(hostEnv = process.env) {
  return Object.entries(hostEnv || {}).filter(([k, v]) => SECRET_HOST_NAME.test(k) && typeof v === 'string' && v.length >= 8).map(([, v]) => v);
}

/** Problems with a target environment; an empty list when it may be passed to `docker run`. */
export function targetEnvProblems(env, hostEnv = process.env) {
  const out = [];
  const secrets = hostSecretValues(hostEnv);
  for (const [k, v] of Object.entries(env || {})) {
    if (!NAME.test(k)) { out.push(`the name ${JSON.stringify(k).slice(0, 40)} is not a variable name`); continue; }
    if (ENV_DENY.test(k)) out.push(`${k} is never passed to a target`);
    if (typeof v !== 'string' || /[\0\n\r]/.test(v) || v.length > 4096) out.push(`${k} has a value that is not one line of text`);
    else if (secrets.some((s) => v.includes(s))) out.push(`${k} holds a value the host keeps under a secret name`);
  }
  return out;
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');
/** JSON with sorted keys at every level, so equal manifests have equal digests. */
export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
}
export const settingsDigest = (m) => sha256(canonical(m));

const VALUE_FLAGS = new Set(['--name', '--label', '--user', '--cap-drop', '--cap-add', '--security-opt', '--tmpfs', '--pids-limit', '--memory', '--memory-swap', '--cpus', '--ulimit', '--hostname', '--network', '--network-alias', '--ip', '--workdir', '--mount', '--env', '--entrypoint', '--runtime', '--cidfile', '--add-host']);
const BOOL_FLAGS = new Set(['--rm', '--detach', '--read-only', '--init', '--interactive']);

function parseMount(s) {
  const o = Object.fromEntries(String(s).split(',').map((p) => { const i = p.indexOf('='); return i < 0 ? [p, true] : [p.slice(0, i), p.slice(i + 1)]; }));
  return { type: o.type ?? null, src: o.src ?? o.source ?? null, dst: o.dst ?? o.target ?? o.destination ?? null, ro: o.readonly === true || o.ro === true };
}

/**
 * The settings of one container, from the `docker run` arguments sandboxRunArgs/helperRunArgs made:
 * runtime, user, capabilities, security options, read-only root, tmpfs, limits, network, address,
 * fixed host entries, mounts, the env names (values only as a digest), the image and a digest of the command.
 */
export function settingsManifest(argv, { role = null } = {}) {
  const a = argv[0] === 'run' ? argv.slice(1) : [...argv];
  const m = { format: 'isokron-sandbox-settings/1', role, runtime: null, user: null, cap_drop: [], cap_add: [], security_opt: [], read_only: false, init: false, tmpfs: [], pids_limit: null, memory: null, memory_swap: null, cpus: null, ulimits: [], network: null, ip: null, aliases: [], hosts: [], workdir: null, mounts: [], env_names: [], env_sha256: null, entrypoint: null, image: null, cmd_sha256: null, cmd_argc: 0 };
  const env = [];
  let i = 0;
  for (; i < a.length; i++) {
    const f = a[i];
    if (BOOL_FLAGS.has(f)) { if (f === '--read-only') m.read_only = true; if (f === '--init') m.init = true; continue; }
    if (!VALUE_FLAGS.has(f)) break;
    const v = a[++i];
    switch (f) {
      case '--runtime': m.runtime = v; break;
      case '--user': m.user = v; break;
      case '--cap-drop': m.cap_drop.push(v); break;
      case '--cap-add': m.cap_add.push(v); break;
      case '--security-opt': m.security_opt.push(v); break;
      case '--tmpfs': m.tmpfs.push(v); break;
      case '--pids-limit': m.pids_limit = Number(v); break;
      case '--memory': m.memory = v; break;
      case '--memory-swap': m.memory_swap = v; break;
      case '--cpus': m.cpus = Number(v); break;
      case '--ulimit': m.ulimits.push(v); break;
      case '--network': m.network = v; break;
      case '--ip': m.ip = v; break;
      case '--network-alias': m.aliases.push(v); break;
      case '--add-host': m.hosts.push(v); break;
      case '--workdir': m.workdir = v; break;
      case '--mount': m.mounts.push(parseMount(v)); break;
      case '--env': env.push(v); break;
      case '--entrypoint': m.entrypoint = v; break;
      default: break; // --name, --label, --hostname, --cidfile: names, not settings
    }
  }
  m.image = a[i] ?? null;
  const cmd = a.slice(i + 1);
  m.cmd_argc = cmd.length;
  m.cmd_sha256 = sha256(JSON.stringify(cmd));
  m.env_names = env.map((e) => e.slice(0, e.indexOf('='))).sort();
  m.env_sha256 = sha256(JSON.stringify([...env].sort()));
  return m;
}

const BYTES = { b: 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 };
export function parseMemory(s) {
  const r = /^(\d+)([bkmg]?)$/i.exec(String(s));
  return r ? Number(r[1]) * BYTES[(r[2] || 'b').toLowerCase()] : null;
}

/**
 * Where a container's actual settings (one element of `docker inspect`) differ from its manifest:
 * runtime, user, capabilities, no-new-privileges, read-only root, limits, network, mounts (only the
 * manifest's volumes and our resolv.conf), and the environment (no denied name, no canary value).
 */
export function inspectMismatches(ins, m, { canaries = [] } = {}) {
  const out = [];
  const hc = (ins && ins.HostConfig) || {}; const cfg = (ins && ins.Config) || {};
  const want = (ok, what) => { if (!ok) out.push(what); };
  want(hc.Runtime === m.runtime, `runtime is ${hc.Runtime}, not ${m.runtime}`);
  want(cfg.User === m.user, `user is ${cfg.User}`);
  const drop = (hc.CapDrop || []).map((c) => String(c).toUpperCase().replace(/^CAP_/, ''));
  want(drop.includes('ALL'), 'capabilities are not all dropped');
  const add = (hc.CapAdd || []).map((c) => String(c).toUpperCase().replace(/^CAP_/, '')).sort();
  want(JSON.stringify(add) === JSON.stringify([...m.cap_add].sort()), `capabilities added: ${add.join(',') || 'none'}`);
  want(!hc.Privileged, 'privileged');
  want((hc.SecurityOpt || []).some((o) => /^no-new-privileges(:true)?$/.test(o)), 'no-new-privileges is not set');
  want(hc.ReadonlyRootfs === m.read_only, 'the root filesystem is not read-only');
  if (m.pids_limit !== null) want(hc.PidsLimit === m.pids_limit, `pids limit is ${hc.PidsLimit}`);
  if (m.memory !== null) want(hc.Memory === parseMemory(m.memory), `memory limit is ${hc.Memory}`);
  if (m.cpus !== null) want(hc.NanoCpus === Math.round(m.cpus * 1e9), `cpu limit is ${hc.NanoCpus}`);
  want(hc.NetworkMode === m.network, `network is ${hc.NetworkMode}`);
  want(!hc.PidMode && !hc.IpcMode?.startsWith?.('host') && hc.UsernsMode !== 'host', 'shares a host namespace');
  want(!(hc.Devices || []).length, 'has host devices');
  want(!(hc.Binds || []).length, 'has -v binds');
  want(canonical([...(hc.ExtraHosts || [])].sort()) === canonical([...(m.hosts || [])].sort()), `fixed host entries differ: ${(hc.ExtraHosts || []).join(',').slice(0, 120) || 'none'}`);
  for (const mt of ins && ins.Mounts ? ins.Mounts : []) {
    const ok = m.mounts.some((x) => (mt.Type === 'volume' && x.type === 'volume' && mt.Name === x.src && mt.Destination === x.dst && mt.RW === !x.ro)
      || (mt.Type === 'bind' && x.type === 'bind' && mt.Source === x.src && mt.Destination === x.dst && mt.RW === false));
    want(ok, `unexpected mount at ${mt.Destination}`);
  }
  const names = (cfg.Env || []).map((e) => String(e).slice(0, String(e).indexOf('=')));
  for (const n of names) if (ENV_DENY.test(n) && n !== 'SURFACE_SANDBOX') out.push(`environment has ${n}`);
  for (const n of m.env_names) want(names.includes(n), `environment lacks ${n}`);
  for (const c of canaries) if (c && (cfg.Env || []).some((e) => String(e).includes(c))) out.push('environment holds a canary value');
  return out;
}
