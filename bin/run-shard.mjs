#!/usr/bin/env node
/**
 * Surface corpus driver: one shard of the target list. For each target it acquires the tool list
 * through every layer that works, runs the checker engine over each list, and writes everything
 * under --out (which the workflow encrypts before upload).
 *
 *   node bin/run-shard.mjs --targets T.json --out DIR [--shard N --shards M] [--only s001,s002]
 *                          [--consume-targets] [--images images.json] [--source-cache DIR] [--lane ci|local]
 *
 * Local only, never set on CI: SURFACE_SOURCE_CACHE (same as --source-cache: <sha>.tar.gz and
 * <sha>.facts.json for a machine that cannot reach GitHub), SURFACE_IMAGE_MIRROR (a registry mirror
 * holding the same digests), SURFACE_INSTALL_CA_FILE (a TLS-inspecting proxy's CA for the installs).
 *
 * Layers, each recorded with whether it worked:
 *   (a) registry  the official MCP Registry entry (how to run it, declared env; rarely a tool list)
 *   (b) live      install in a sandbox container, start the server with no network, and send
 *                 initialize, tools/list, prompts/list, resources/list, resources/templates/list
 *   (c) static    tool registrations read from the source archive of the pinned commit
 *   (d) readme    tool names read from the README
 *
 * Isolation. No target code runs on the host. The host does three things with target data: it
 * fetches bytes from fixed hosts (GitHub, the MCP Registry), pipes them into containers, and parses
 * JSON that containers print. Target code runs only in `sandboxRunArgs` containers: user 10001,
 * every capability dropped, no-new-privileges, read-only root, memory, pid and CPU limits, named
 * volumes only. The install step is on an --internal network and reaches the package registry only
 * through our allowlist proxy; the server itself runs with --network none (stdio) or on an
 * --internal network shared with our probe container only (http). At a time limit the container is
 * removed, which ends every process in it. Nothing is called: no tool, no prompt, no resource read.
 *
 * Public output (stdout): one "run finished, exit N" line per target, in an order shuffled per run,
 * with no target id or name. N: 0 the target ran to completion (whatever the layers found), 124 it
 * hit its time limit, 125 harness error. The process exits 0 when every N is 0.
 */
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { Docker, HarnessError, checkDockerVersion, checkPinned, helperRunArgs, sandboxRunArgs, LIMITS, LABEL_RUN, LABEL_TARGET } from '../src/docker.mjs';
import { ID, P, idNumber, launchPlan, shardTargets, timeoutOf, validateList } from '../src/targets.mjs';
import { githubFacts, registryEntry, sourceArchive } from '../src/sources.mjs';
import { dummyValue, isSecretName } from '../src/env-refs.mjs';
import { sdkFromFile } from '../src/sdk.mjs';
import { buildRow, buildState, RECORD_FORMAT } from '../src/record.mjs';
import { probeStdio, listed, PROTOCOL_OFFERED } from '../sandbox/probe.mjs';

export const RUN_FORMAT = 'isokron-surface-run/1';
export const LABEL = 'surface corpus: calibration data, not a finding';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const say = (line) => process.stdout.write(`${line}\n`);

const PROBE_MS = Number(process.env.SURFACE_PROBE_MS || 60_000);
const STEP_MS = 120_000;
const OUT_CAP = 96 * 1024 * 1024;
const LOCK_CAP = 16 * 1024 * 1024;
const MAX_ENV = 40;
const PROXY_PORT = 8080;

export function parseArgs(argv) {
  const o = { lane: 'local', shard: 1, shards: 1, only: null, consume: false, images: join(root, 'images.json'), sourceCache: process.env.SURFACE_SOURCE_CACHE || null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => { if (i + 1 >= argv.length) throw new HarnessError(`${a} needs a value`); return argv[++i]; };
    if (a === '--targets') o.targets = v();
    else if (a === '--out') o.out = v();
    else if (a === '--shard') o.shard = Number(v());
    else if (a === '--shards') o.shards = Number(v());
    else if (a === '--only') o.only = v().split(',').filter(Boolean);
    else if (a === '--consume-targets') o.consume = true;
    else if (a === '--images') o.images = v();
    else if (a === '--source-cache') o.sourceCache = v();
    else if (a === '--lane') o.lane = v();
    else throw new HarnessError(`unknown option ${a}`);
  }
  if (!o.targets || !o.out) throw new HarnessError('usage: run-shard.mjs --targets T.json --out DIR [--shard N --shards M] [--only IDS]');
  if (!(Number.isInteger(o.shards) && o.shards >= 1 && o.shards <= 64 && Number.isInteger(o.shard) && o.shard >= 1 && o.shard <= o.shards)) throw new HarnessError('--shard must be between 1 and --shards (at most 64)');
  if (!['ci', 'local'].includes(o.lane)) throw new HarnessError('--lane must be ci or local');
  if (o.only && !o.only.every((x) => ID.test(x))) throw new HarnessError('--only takes target ids such as s001,s002');
  return o;
}

/** Images from images.json, every one pinned by digest. SURFACE_IMAGE_MIRROR (never set on CI) swaps docker.io for a mirror of the same digests. */
export function loadImages(file, mirror = process.env.SURFACE_IMAGE_MIRROR || '') {
  const j = JSON.parse(readFileSync(file, 'utf8'));
  const out = {};
  for (const k of ['node24', 'node22', 'python', 'go']) {
    let ref = checkPinned(j[k], k);
    if (mirror) { if (!/^[a-z0-9.-]+(?::[0-9]+)?$/.test(mirror)) throw new HarnessError('SURFACE_IMAGE_MIRROR is not a host name'); ref = ref.replace(/^docker\.io\//, `${mirror}/`); }
    out[k] = ref;
  }
  return out;
}

export function shuffled(list, seedHex) {
  const a = [...list];
  let s = BigInt(`0x${seedHex.slice(0, 16)}`) || 1n;
  const next = () => { s ^= s << 13n; s &= 0xffffffffffffffffn; s ^= s >> 7n; s ^= s << 17n; s &= 0xffffffffffffffffn; return Number(s % 1000003n); };
  for (let i = a.length - 1; i > 0; i--) { const j = next() % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

/**
 * The env names a probe sets: the list's own, the registry's required ones, and the README's secret-named ones
 * (keys, tokens, passwords). A README also names switches and paths (LOG_LEVEL, *_PATH, *_URL, *_ENABLED); a dummy
 * value for those changes how the server starts without standing in for a credential, so they are recorded but not set.
 * Values are dummies.
 */
export function envPlan(launch, registry, stat) {
  const fromList = Object.keys((launch && launch.env) || {});
  const fromRegistry = ((registry && registry.env) || []).filter((e) => e.required).map((e) => e.name);
  const fromReadme = (stat && stat.env_refs && stat.env_refs.readme) || [];
  const fromSource = (stat && stat.env_refs && stat.env_refs.source) || [];
  const ok = (n) => /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(n) && !/^(PATH|HOME|TMPDIR|LD_.*|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|PYTHON.*|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_.*|DOCKER_.*|GITHUB_.*|ACTIONS_.*|RUNNER_.*|SURFACE_.*|CORPUS_.*)$/i.test(n);
  const used = [...new Set([...fromList, ...fromRegistry, ...fromReadme.filter(isSecretName)])].filter(ok).slice(0, MAX_ENV);
  const env = {};
  for (const n of used) { const v = launch && launch.env ? launch.env[n] : undefined; env[n] = typeof v === 'string' ? v : dummyValue(n); }
  return { env, names: { list: fromList, registry: fromRegistry, readme: fromReadme, source: fromSource, used } };
}

function writeJson(file, data) { writeFileSync(file, `${JSON.stringify(data)}\n`); }
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const safeParse = (buf) => { try { const j = JSON.parse(buf.toString('utf8')); return j && typeof j === 'object' ? j : null; } catch { return null; } };

async function prepare(ctx, dk) {
  const v = await dk.d(['version', '--format', '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'], { keepStdout: true });
  if (v.exit !== 0) throw new HarnessError('docker is not available');
  const [ver, osArch] = v.stdout.toString().trim().split(' ');
  checkDockerVersion(ver);
  if (!String(osArch).startsWith('linux/')) throw new HarnessError('containers must be Linux');
  ctx.runner.docker = ver; ctx.runner.container_platform = osArch;
  const ncpu = Number((await dk.d(['info', '--format', '{{.NCPU}}'], { keepStdout: true, logStdout: false })).stdout.toString().trim());
  ctx.cpus = Number.isInteger(ncpu) && ncpu >= 1 ? Math.min(LIMITS.cpus, ncpu) : 1;
  ctx.imageIds = { node24: await dk.image(ctx.images.node24, 'node24') };
  // Our in-container code (sandbox/, src/, engine/), read-only in every container. Copied through
  // stdin into a named volume: no host path is ever mounted.
  ctx.toolsVol = await dk.volume(`surface-${ctx.runId}-tools`);
  const tar = spawnSync('tar', ['-C', root, '-cf', '-', '--owner=0', '--group=0', '--mode=a+rX,go-w', 'sandbox', 'src', 'engine'], { maxBuffer: 64 * 1024 * 1024 });
  if (tar.status !== 0) throw new HarnessError('packing the sandbox tools failed');
  ctx.toolsSha = sha256(tar.stdout);
  await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: ctx.images.node24, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools }], cmd: ['tar', '-x', '-f', '-', '--no-same-owner', '-C', P.tools] }), { input: tar.stdout }), 'tools volume');
  ctx.caEnv = {};
  ctx.installCa = null;
  if (process.env.SURFACE_INSTALL_CA_FILE) {
    // A machine behind a TLS-inspecting proxy (never CI): the CA is added to the tools volume, read-only everywhere.
    const ca = readFileSync(process.env.SURFACE_INSTALL_CA_FILE);
    await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: ctx.images.node24, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools }], cmd: ['sh', '-c', 'cat > /opt/surface/ca.pem && chmod 0444 /opt/surface/ca.pem'] }), { input: ca }), 'install CA');
    ctx.installCa = sha256(ca);
    const f = `${P.tools}/ca.pem`;
    ctx.caEnv = { NODE_EXTRA_CA_CERTS: f, SSL_CERT_FILE: f, PIP_CERT: f, REQUESTS_CA_BUNDLE: f, npm_config_cafile: f };
  }
  // One network with egress for the allowlist proxies of this shard; target containers never join it.
  ctx.outNet = await dk.network(`surface-${ctx.runId}-out`, false);
}

/** What `docker run` itself costs in this sandbox: our null server, probed the way targets are. */
async function baseline(ctx, dk) {
  const name = dk.name(null, 'base');
  const argv = sandboxRunArgs({ name, image: ctx.images.node24, network: 'none', labels: dk.labels(), stdin: true, cpus: ctx.cpus, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], env: runEnv({}), cmd: ['node', `${P.tools}/sandbox/null-server.mjs`] });
  const p = await probeStdio(['docker', ...argv], { protocol: PROTOCOL_OFFERED, timeoutMs: PROBE_MS, env: dk.env });
  await dk.kill(name);
  return listed(p) ? p.timing.initialize_ms : null;
}

const runEnv = (extra) => ({ HOME: P.home, TMPDIR: '/tmp', NO_COLOR: '1', DO_NOT_TRACK: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1', npm_config_update_notifier: 'false', SURFACE_SANDBOX: '1', ...extra });
const installEnv = (ctx, extra) => ({
  HOME: `${P.work}/home`, TMPDIR: '/tmp', NO_COLOR: '1', DO_NOT_TRACK: '1', SURFACE_SANDBOX: '1', CI: '1',
  npm_config_cache: `${P.work}/home/.npm`, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false',
  PIP_CACHE_DIR: `${P.work}/home/.cache/pip`, PIP_DISABLE_PIP_VERSION_CHECK: '1', PIP_NO_INPUT: '1',
  HTTPS_PROXY: `http://egress:${PROXY_PORT}`, https_proxy: `http://egress:${PROXY_PORT}`, HTTP_PROXY: `http://egress:${PROXY_PORT}`, http_proxy: `http://egress:${PROXY_PORT}`, NO_PROXY: '', no_proxy: '',
  ...ctx.caEnv, ...extra,
});

async function runTarget(t, list, ctx, dk) {
  const id = t.id;
  const dir = join(ctx.out, id);
  mkdirSync(dir, { recursive: true });
  const log = join(dir, 'steps.log');
  const tdk = Object.create(dk); tdk.log = log;
  const t0 = Date.now();
  const deadline = t0 + timeoutOf(t, list) * 1000;
  const left = (cap = Infinity) => Math.min(deadline, Date.now() + cap);
  const rec = {
    format: RECORD_FORMAT, target: id, run: ctx.runId, started_at: new Date().toISOString(), finished_at: null,
    list_entry: t, time_limit_s: timeoutOf(t, list),
    source: null, registry: null, static: null, install: null, probes: {}, env: null, analysis: null,
    layers: { registry: false, live: false, static: false, readme: false }, errors: [], public_exit: 125, timed_out: false,
    files: [],
  };
  const timing = { static_ms: null, install_ms: null, probe_ms: null, analyse_ms: null, total_ms: null };
  let stat = null; let registry = null; let facts = null; let bare = null; let withEnv = null; let primary = null; let analysis = null; let lockHits = []; let resolved = null; let names = null;
  const keep = (name, data) => { writeJson(join(dir, name), data); rec.files.push(name); };
  const keepRaw = (name, buf) => { writeFileSync(join(dir, name), buf); rec.files.push(name); };
  const lbl = dk.labels(id);
  const helper = (o, opts = {}) => tdk.d(helperRunArgs({ name: dk.name(id, 'h'), image: ctx.images.node24, labels: lbl, cpus: ctx.cpus, ...o }), opts);
  const timedOut = () => Date.now() >= deadline;

  try {
    // 1. Repository facts and the commit (host fetch, fixed hosts).
    facts = await githubFacts(t, { fetchFn: ctx.fetchFn, token: ctx.githubToken, cacheDir: ctx.sourceCache });
    rec.source = { github: facts };
    if (!facts.sha) throw new HarnessError('the commit could not be resolved');

    // 2. Layers (c) and (d): the source archive goes to the static reader's container on stdin.
    const s0 = Date.now();
    try {
      const a = await sourceArchive(t.repo, facts.sha, { fetchFn: ctx.fetchFn, cacheDir: ctx.sourceCache });
      rec.source.archive = { sha256: a.sha256, bytes: a.bytes, via: a.via };
      const r = await helper({ stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', '--max-old-space-size=1536', `${P.tools}/sandbox/static.mjs`, ...(t.subdir ? ['--subdir', t.subdir] : [])] }, { input: a.buf, keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: left(STEP_MS * 2), onTimeout: () => dk.sweep(id) });
      stat = r.exit === 0 && !r.stdout_truncated ? safeParse(r.stdout) : null;
      if (stat && stat.format && !stat.error) {
        keep('static.json', stat);
        rec.static = { ok: true, best: stat.static.best, candidates: stat.static.candidates.map((c) => ({ kind: c.kind, fidelity: c.fidelity, tools: c.tools.length, path: c.path ?? null })), readme_tools: stat.readme ? stat.readme.tools.length : 0, languages: stat.languages, primary_language: stat.primary_language, sdk: stat.sdk, manifests: stat.manifests, license_files: stat.license_files, subdir_found: stat.archive.subdir_found, documented_commands: stat.documented_commands, env_refs: stat.env_refs };
        rec.layers.static = !!stat.static.best;
        rec.layers.readme = !!(stat.readme && stat.readme.tools.length);
      } else { rec.static = { ok: false, exit: r.exit, timed_out: r.timed_out, error: stat && stat.error ? stat.error : 'the static reader gave no result' }; stat = null; }
    } catch (e) { rec.static = { ok: false, error: String(e.message).slice(0, 200) }; rec.errors.push({ step: 'source', error: String(e.message).slice(0, 200) }); }
    timing.static_ms = Date.now() - s0;

    // 3. Layer (a): the MCP Registry entry (by the list's name, else the package's own mcpName).
    const regName = t.registry ?? (stat && stat.package_json && typeof stat.package_json.mcpName === 'string' && /^[A-Za-z0-9][A-Za-z0-9.-]{0,120}\/[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/.test(stat.package_json.mcpName) ? stat.package_json.mcpName : null);
    if (regName && !timedOut()) {
      registry = await registryEntry(regName, { fetchFn: ctx.fetchFn });
      keep('registry.json', registry);
      rec.registry = { name_from: t.registry ? 'list' : 'mcpName', ok: registry.ok, found: registry.found, version: registry.version, packages: registry.packages, remotes: registry.remotes, env: registry.env, tools: Array.isArray(registry.tools) ? registry.tools.length : 0, error: registry.error };
      rec.layers.registry = !!registry.found;
    }

    // 4. Layer (b): install with allowlisted egress, then run with no network and probe.
    const plan0 = envPlan(t.launch, registry, stat);
    names = plan0.names;
    rec.env = { names, secret_named: names.used.filter(isSecretName), values: 'dummy values only; never a credential' };
    if (t.launch && !timedOut()) {
      const i0 = Date.now();
      const plan = launchPlan(t.launch);
      const inst = { kind: t.launch.kind, steps: [], ok: false, egress: [], image: null, resolved_version: null };
      rec.install = inst;
      let work = null; let entry = null; let image = null;
      try {
        if (plan.targetImage) {
          image = checkPinned(plan.targetImage, 'target');
          inst.image = image;
          const p0 = Date.now();
          const pull = await tdk.d(['pull', '-q', image], { deadline: left(600_000) });
          inst.steps.push({ name: 'pull', exit: pull.exit, timed_out: pull.timed_out, ms: Date.now() - p0 });
          if (pull.exit !== 0) throw new HarnessError('the target image could not be pulled');
          inst.ok = true;
        } else {
          image = ctx.images[plan.image];
          inst.image = image;
          ctx.imageIds[plan.image] ??= await dk.image(image, plan.image);
          work = await dk.volume(`surface-${ctx.runId}-${id}-work`, id);
          await dk.must(tdk.d(helperRunArgs({ name: dk.name(id, 'h'), image: ctx.images.node24, user: '0:0', labels: lbl, mounts: [{ src: work, dst: P.work }], capAdd: ['CHOWN'], cmd: ['sh', '-c', 'mkdir -p /work/home /work/lock && chown -R 10001:10001 /work'] })), 'work volume');
          // The install network has no route out; the proxy container is its only door.
          const inNet = await dk.network(`surface-${ctx.runId}-${id}-in`, true, id);
          const proxy = dk.name(id, 'proxy');
          await dk.must(tdk.d(helperRunArgs({ name: proxy, image: ctx.images.node24, network: ctx.outNet, detach: true, labels: lbl, memory: '256m', mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/egress-proxy.mjs`, String(PROXY_PORT), ...plan.registries] })), 'egress proxy');
          await dk.must(tdk.d(['network', 'connect', '--alias', 'egress', inNet, proxy]), 'egress proxy network');
          let okAll = true;
          for (const step of plan.install) {
            if (timedOut()) { okAll = false; break; }
            const s1 = Date.now();
            const name = dk.name(id, 'i');
            const r = await tdk.d(sandboxRunArgs({ name, image, network: inNet, labels: lbl, cpus: ctx.cpus, workdir: P.work, mounts: [{ src: work, dst: P.work }, { src: ctx.toolsVol, dst: P.tools, ro: true }], env: installEnv(ctx, step.env || {}), cmd: step.cmd }), { deadline: left(), keepStdout: !!step.out, logStdout: !step.out, cap: 1024 * 1024, onTimeout: () => dk.kill(name) });
            const s = { name: step.name, exit: r.exit, timed_out: r.timed_out, ms: Date.now() - s1 };
            if (step.out) { const j = safeParse(r.stdout); if (step.name === 'entry') entry = j && typeof j.script === 'string' && j.script.startsWith(`${P.work}/pkg/`) && !/[\u0000\n]/.test(j.script) ? j : null; s.result = j; }
            inst.steps.push(s);
            if (r.exit !== 0 || (step.name === 'entry' && !entry)) { okAll = false; break; }
          }
          // What the install tried to reach, allowed or refused: part of the record.
          const pl = await tdk.d(['logs', proxy], { keepStdout: true, logStdout: false, cap: 4 * 1024 * 1024 });
          inst.egress = pl.stdout.toString('utf8').split('\n').filter(Boolean).slice(0, 5000).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
          inst.egress_refused = inst.egress.filter((e) => e.allowed === false && e.host).length;
          await dk.kill(proxy);
          inst.ok = okAll;
          // Lock files, read out through a helper with no network (target-written: data only, size-capped).
          for (const lk of plan.locks) {
            const r = await helper({ mounts: [{ src: work, dst: P.work, ro: true }], cmd: ['sh', '-c', 'test -f "$1" && test ! -L "$1" && head -c 16777216 "$1"', 'sh', lk.path] }, { keepStdout: true, logStdout: false, cap: LOCK_CAP, deadline: left(STEP_MS) });
            if (r.exit === 0 && r.stdout.length) {
              keepRaw(`lock-${lk.name}`, r.stdout);
              const hits = sdkFromFile(lk.name, r.stdout.toString('utf8')).map((h) => ({ ...h, kind: 'installed', depth: -1, path: lk.name }));
              lockHits.push(...hits);
              inst.lock = { name: lk.name, bytes: r.stdout.length, sha256: sha256(r.stdout), sdk_hits: hits };
            }
          }
          if (entry) { inst.resolved_version = entry.version; inst.engines_node = entry.engines; }
          if (t.launch.kind === 'pypi' && inst.lock) {
            const m = new RegExp(`^${t.launch.package.replace(/[-_.]+/g, '[-_.]+')}==([\\w.+!-]+)$`, 'mi').exec(readFileSync(join(dir, 'lock-freeze.txt'), 'utf8'));
            if (m) inst.resolved_version = m[1].slice(0, 64);
          }
          if (t.launch.kind === 'go' && inst.lock) {
            const m = /^\s*mod\s+\S+\s+(v[\w.+-]+)/m.exec(readFileSync(join(dir, 'lock-go-version-m.txt'), 'utf8'));
            if (m) inst.resolved_version = m[1].slice(0, 80);
          }
          resolved = inst.resolved_version;
        }
        timing.install_ms = Date.now() - i0;

        if (inst.ok && !timedOut()) {
          const p0 = Date.now();
          const runImage = plan.targetImage ? image : ctx.images[plan.runImage ?? plan.image];
          if (!plan.targetImage) ctx.imageIds[plan.runImage ?? plan.image] ??= await dk.image(runImage, 'run');
          const cmd = plan.run(entry);
          const mounts = [...(work ? [{ src: work, dst: P.work, ro: true }] : [])];
          const probeOnce = async (env, tag) => {
            if (timedOut()) return null;
            const transport = t.launch.transport ?? 'stdio';
            let p;
            if (transport === 'stdio') {
              const name = dk.name(id, 's');
              const argv = sandboxRunArgs({ name, image: runImage, network: 'none', labels: lbl, stdin: true, cpus: ctx.cpus, mounts, env: runEnv(env), cmd, entrypoint: plan.entrypoint ?? null });
              p = await probeStdio(['docker', ...argv], { protocol: PROTOCOL_OFFERED, timeoutMs: Math.max(1000, Math.min(PROBE_MS, deadline - Date.now())), env: dk.env });
              await dk.kill(name);
            } else {
              // Streamable HTTP: the server and our probe share one --internal network and nothing else.
              const net = await dk.network(`surface-${ctx.runId}-${id}-run${++dk.n}`, true, id);
              const name = dk.name(id, 's');
              await tdk.d(sandboxRunArgs({ name, image: runImage, network: net, aliases: ['server'], detach: true, labels: lbl, cpus: ctx.cpus, mounts, env: runEnv(env), cmd, entrypoint: plan.entrypoint ?? null }), { deadline: left(STEP_MS) });
              const ms = Math.max(1000, Math.min(PROBE_MS, deadline - Date.now()));
              const r = await helper({ network: net, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/probe.mjs`, 'http', String(ms), PROTOCOL_OFFERED, `http://server:${t.launch.http.port}${t.launch.http.path}`] }, { keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: Date.now() + ms + 15_000 });
              p = safeParse(r.stdout) || { format: 'isokron-surface-probe/1', mode: 'http', error: 'the HTTP probe gave no result', lists: {}, transcript: [], transport: {} };
              const logs = await tdk.d(['logs', name], { keepStdout: true, logStdout: false, cap: 4 * 1024 * 1024 });
              p.stderr = logs.stdout.toString('utf8').slice(0, 4 * 1024 * 1024); p.stderr_bytes = logs.stdout_bytes;
              await dk.kill(name);
              await tdk.d(['network', 'rm', net]);
            }
            p.env_names = Object.keys(env);
            keep(`probe-${tag}.json`, p);
            return p;
          };
          bare = await probeOnce({}, 'bare');
          if (names.used.length) withEnv = await probeOnce(plan0.env, 'env');
          primary = withEnv && listed(withEnv) ? withEnv : bare && listed(bare) ? bare : null;
          for (const [tag, p] of [['bare', bare], ['env', withEnv]]) {
            if (!p) continue;
            const tl = p.lists && p.lists['tools/list'];
            rec.probes[tag] = { ok: listed(p), era: p.era ?? null, error: p.error ?? null, initialize_error: p.initialize_error ?? null, tools_error: tl ? tl.error : null, exit: p.transport ? p.transport.exit ?? null : null, signal: p.transport ? p.transport.signal ?? null : null, timing: p.timing ?? null, transcript_bytes: p.transcript_bytes ?? null, stderr_bytes: p.stderr_bytes ?? null, env_names: p.env_names };
          }
          rec.layers.live = !!primary;
          if (primary) rec.server = { initialize: primary.initialize ?? null, era: primary.era };
          timing.probe_ms = Date.now() - p0;
        }
      } catch (e) {
        if (!(e instanceof HarnessError)) throw e;
        rec.errors.push({ step: 'live', error: String(e.message).slice(0, 200) });
      }
    }

    // 5. The checker engine over every list acquired, in a container with no network.
    const a0 = Date.now();
    const cands = stat ? stat.static.candidates.slice(0, 4).map((c) => ({ kind: c.kind, fidelity: c.fidelity, tools: c.tools })) : [];
    const input = {
      live_pages: primary && primary.lists['tools/list'].raw_pages ? primary.lists['tools/list'].raw_pages : null,
      static: cands, readme: stat && stat.readme && stat.readme.tools.length ? stat.readme.tools.map((x) => x.tool) : null,
      registry: registry && Array.isArray(registry.tools) ? registry.tools : null,
      probe: primary ? { lists: Object.fromEntries(Object.entries(primary.lists).map(([m, L]) => [m, { ok: L.ok, items: L.items, pages: L.pages, error_code: L.error_code, ms: L.ms }])), initialize: primary.initialize } : null,
    };
    if (input.live_pages || cands.length || input.readme || input.registry) {
      const r = await helper({ stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', '--max-old-space-size=1536', `${P.tools}/sandbox/analyse.mjs`] }, { input: Buffer.from(JSON.stringify(input)), keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: Math.max(left(STEP_MS * 2), Date.now() + 30_000), onTimeout: () => dk.sweep(id) });
      analysis = r.exit === 0 && !r.stdout_truncated ? safeParse(r.stdout) : null;
      if (analysis && !analysis.error) { keep('analysis.json', analysis); rec.analysis = { ok: true, runs: Object.fromEntries(Object.entries(analysis.runs).map(([k, v]) => [k, { ok: v.ok, error: v.error ?? null, error_type: v.error_type ?? null, tool_count: v.tool_count ?? null, catalog_hash: v.catalog_hash ?? null, grades: v.grades ?? null }])) }; } else { rec.analysis = { ok: false, exit: r.exit, timed_out: r.timed_out }; rec.errors.push({ step: 'analyse', error: 'the analyser gave no result' }); analysis = null; }
    }
    timing.analyse_ms = Date.now() - a0;
    rec.timed_out = timedOut();
    rec.public_exit = rec.timed_out ? 124 : rec.errors.some((e) => e.step === 'analyse') ? 125 : 0;
  } catch (e) {
    rec.errors.push({ step: 'harness', error: String(e && e.message).slice(0, 300), harness: e instanceof HarnessError });
    rec.public_exit = timedOut() ? 124 : 125;
    rec.timed_out = timedOut();
  } finally {
    try { await dk.sweep(id); } catch { /* the shard's last sweep runs too */ }
  }
  timing.total_ms = Date.now() - t0;
  rec.timing = timing;
  rec.finished_at = new Date().toISOString();
  const row = buildRow({ id, publicExit: rec.public_exit, launch: t.launch ?? null, facts, registry, stat, bare, withEnv, primary, analysis, envNames: names, lockHits, timing, baselineMs: ctx.baselineMs });
  const state = buildState({ id, row, analysis, sha: facts ? facts.sha : null, resolved });
  rec.row = row;
  keep('record.json', rec);
  appendFileSync(join(ctx.out, '_shard', 'rows.jsonl'), `${JSON.stringify(row)}\n`);
  appendFileSync(join(ctx.out, '_shard', 'state.jsonl'), `${JSON.stringify(state)}\n`);
  return rec.public_exit;
}

export async function main(argv = process.argv.slice(2), { fetchFn = fetch } = {}) {
  const o = parseArgs(argv);
  const list = validateList(JSON.parse(readFileSync(o.targets, 'utf8')));
  if (o.consume) rmSync(o.targets, { force: true });
  const runId = randomBytes(6).toString('hex');
  const out = resolve(o.out);
  mkdirSync(join(out, '_shard'), { recursive: true });
  const ctx = {
    runId, out, lane: o.lane, images: loadImages(o.images), sourceCache: o.sourceCache ? resolve(o.sourceCache) : null, fetchFn,
    githubToken: process.env.GH_TOKEN || null,
    runner: { os: platform(), arch: arch(), kernel: release(), node: process.version },
    baselineMs: null,
  };
  const dk = new Docker({ runId, log: join(out, '_shard', 'docker.log') });
  const targets = shardTargets(list.targets, o.shard, o.shards, o.only);
  const engine = JSON.parse(readFileSync(join(root, 'engine', 'VENDORED.json'), 'utf8'));
  const shard = { format: RUN_FORMAT, label: LABEL, run: runId, lane: o.lane, shard: o.shard, shards: o.shards, only: o.only, started_at: new Date().toISOString(), finished_at: null, targets: targets.map((t) => t.id), list_total: list.targets.length, engine: { commit: engine.commit, rubric_version: engine.rubric_version, checks: engine.checks, core_sha256: engine.files[0].sha256 }, images: ctx.images, limits: LIMITS, probe_ms: PROBE_MS, protocol_offered: PROTOCOL_OFFERED, runner: ctx.runner, results: {}, harness_error: null };
  const exits = [];
  say(LABEL);
  try {
    await prepare(ctx, dk);
    ctx.baselineMs = await baseline(ctx, dk);
    Object.assign(shard, { tools_sha256: ctx.toolsSha, install_ca: ctx.installCa, baseline_initialize_ms: ctx.baselineMs, image_ids: ctx.imageIds, cpus: ctx.cpus });
    for (const t of shuffled(targets, runId)) {
      let rc = 125;
      try { rc = await runTarget(t, list, ctx, dk); } catch (e) { appendFileSync(join(out, '_shard', 'driver-errors.log'), `${t.id}: ${String(e && e.stack).slice(0, 2000)}\n`); }
      shard.results[t.id] = rc;
      exits.push(rc);
      say(`run finished, exit ${rc}`);
    }
  } catch (e) {
    shard.harness_error = String(e && e.message).slice(0, 300);
    appendFileSync(join(out, '_shard', 'driver-errors.log'), `${String(e && e.stack).slice(0, 4000)}\n`);
    exits.push(125);
    say('run finished, exit 125');
  } finally {
    try { await dk.sweep(); } catch { /* the workflow's own sweep follows */ }
  }
  shard.finished_at = new Date().toISOString();
  shard.image_ids = ctx.imageIds;
  writeJson(join(out, '_shard', 'shard.json'), shard);
  for (const f of ['rows.jsonl', 'state.jsonl']) if (!existsSync(join(out, '_shard', f))) writeFileSync(join(out, '_shard', f), '');
  return exits.every((x) => x === 0) ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((rc) => process.exit(rc), (e) => { process.stderr.write(`${e instanceof HarnessError ? e.message : e && e.stack}\n`); say('run finished, exit 125'); process.exit(1); });
}

export { LABEL_RUN, LABEL_TARGET, idNumber };
