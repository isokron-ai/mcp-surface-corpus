// The target list (format isokron-surface-targets/1): validation, sharding and the launch plan.
// The real list is never in the repository in clear text (targets/targets.json.age); the public
// example (targets/example.targets.json) names three reference servers and has the same format.
// targets/FORMAT.md documents every field.

export const TARGETS_FORMAT = 'isokron-surface-targets/1';
export const ID = /^s[0-9]{3,4}$/;
export const MAX_TIMEOUT_S = 1800;
export const DEFAULT_TIMEOUT_S = 600;
export const KINDS = ['npm', 'pypi', 'go', 'docker'];
export const TRANSPORTS = ['stdio', 'http'];

export class ListError extends Error {}
const fail = (m) => { throw new ListError(m); };

const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const SHA = /^[0-9a-f]{40}$/;
const REF = /^(?!-)[A-Za-z0-9._/-]{1,120}$/;
const SUBDIR = /^(?![/.])(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._@+/-]{1,200}$/;
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]{0,80}\/)?[a-z0-9][a-z0-9._~-]{0,120}$/;
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,120}[A-Za-z0-9])?$/;
const GO_MODULE = /^[a-z0-9][A-Za-z0-9.-]*\.[a-z]{2,}(?:\/[A-Za-z0-9._~-]+)+$/;
const SEMVER = /^[0-9]+(?:\.[0-9A-Za-z-]+){0,3}(?:[-+.][0-9A-Za-z.+-]{1,60})?$/;
const GO_VERSION = /^(?:v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,80})?|[0-9a-f]{12,40})$/;
const BIN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;
const IMAGE = /^[a-z0-9][a-z0-9./_-]{0,200}(?::[A-Za-z0-9._-]{1,120})?@sha256:[0-9a-f]{64}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const REGISTRY_NAME = /^[A-Za-z0-9][A-Za-z0-9.-]{0,120}\/[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;
// Names the harness or the runtime owns: a list may not set them.
const RESERVED_ENV = /^(PATH|HOME|TMPDIR|LD_[A-Z_]+|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|PYTHON(PATH|HOME|STARTUP)|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_(FILE|DIR)|DOCKER_.*|GITHUB_.*|ACTIONS_.*|RUNNER_.*|SURFACE_.*|CORPUS_.*)$/i;

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const only = (o, keys, what) => { for (const k of Object.keys(o)) if (!keys.includes(k)) fail(`${what}: unknown field ${JSON.stringify(k.slice(0, 40))}`); };
const strList = (a, what, max = 40) => {
  if (a === undefined) return [];
  if (!Array.isArray(a) || a.length > max || !a.every((x) => typeof x === 'string' && x.length <= 2000 && !/[\u0000\n\r]/.test(x))) fail(`${what} must be a list of at most ${max} strings`);
  return a;
};

export function validateLaunch(l, what) {
  if (!isObj(l)) fail(`${what}.launch must be an object`);
  if (!KINDS.includes(l.kind)) fail(`${what}.launch.kind must be one of ${KINDS.join(', ')}`);
  const common = ['kind', 'args', 'env', 'transport', 'http', 'note'];
  const transport = l.transport ?? 'stdio';
  if (!TRANSPORTS.includes(transport)) fail(`${what}.launch.transport must be stdio or http`);
  if (transport === 'http') {
    if (!isObj(l.http)) fail(`${what}.launch.http is required for the http transport`);
    only(l.http, ['port', 'path'], `${what}.launch.http`);
    if (!Number.isInteger(l.http.port) || l.http.port < 1024 || l.http.port > 65535) fail(`${what}.launch.http.port must be a whole number from 1024 to 65535`);
    if (typeof l.http.path !== 'string' || !/^\/[A-Za-z0-9._~/-]{0,200}$/.test(l.http.path)) fail(`${what}.launch.http.path must start with / and hold URL path characters only`);
  } else if (l.http !== undefined) fail(`${what}.launch.http is for the http transport only`);
  strList(l.args, `${what}.launch.args`);
  if (l.env !== undefined) {
    if (!isObj(l.env) || Object.keys(l.env).length > 60) fail(`${what}.launch.env must be an object of at most 60 names`);
    for (const [k, v] of Object.entries(l.env)) {
      if (!ENV_NAME.test(k) || RESERVED_ENV.test(k)) fail(`${what}.launch.env: ${JSON.stringify(k.slice(0, 40))} is not a name a target may set`);
      if (!(v === null || (typeof v === 'string' && v.length <= 500 && !/[\u0000\n\r]/.test(v)))) fail(`${what}.launch.env.${k} must be null (a dummy value is made) or a short string`);
    }
  }
  if (l.kind === 'npm') {
    only(l, [...common, 'package', 'version', 'bin', 'install_scripts', 'node'], `${what}.launch`);
    if (typeof l.package !== 'string' || !NPM_NAME.test(l.package)) fail(`${what}.launch.package is not an npm package name`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && SEMVER.test(l.version)))) fail(`${what}.launch.version must be an exact version or "latest"`);
    if (l.bin !== undefined && !(typeof l.bin === 'string' && BIN.test(l.bin))) fail(`${what}.launch.bin is not a bin name`);
    if (l.install_scripts !== undefined && typeof l.install_scripts !== 'boolean') fail(`${what}.launch.install_scripts must be true or false`);
    if (l.node !== undefined && !['22', '24'].includes(l.node)) fail(`${what}.launch.node must be "22" or "24"`);
  } else if (l.kind === 'pypi') {
    only(l, [...common, 'package', 'version', 'entry'], `${what}.launch`);
    if (typeof l.package !== 'string' || !PYPI_NAME.test(l.package)) fail(`${what}.launch.package is not a PyPI project name`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && SEMVER.test(l.version)))) fail(`${what}.launch.version must be an exact version or "latest"`);
    if (l.entry !== undefined && !(typeof l.entry === 'string' && BIN.test(l.entry))) fail(`${what}.launch.entry is not a console-script name`);
  } else if (l.kind === 'go') {
    only(l, [...common, 'module', 'version'], `${what}.launch`);
    if (typeof l.module !== 'string' || !GO_MODULE.test(l.module)) fail(`${what}.launch.module is not a Go package path`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && GO_VERSION.test(l.version)))) fail(`${what}.launch.version must be vX.Y.Z, a commit, or "latest"`);
  } else {
    only(l, [...common, 'image', 'entrypoint'], `${what}.launch`);
    if (typeof l.image !== 'string' || !IMAGE.test(l.image)) fail(`${what}.launch.image must be pinned by digest (name@sha256:...)`);
    if (l.entrypoint !== undefined && !(typeof l.entrypoint === 'string' && /^[A-Za-z0-9_./-]{1,200}$/.test(l.entrypoint))) fail(`${what}.launch.entrypoint is not a path`);
  }
  return l;
}

export function validateTarget(t, i = 0) {
  const what = `targets[${i}]`;
  if (!isObj(t)) fail(`${what} must be an object`);
  only(t, ['id', 'repo', 'commit', 'ref', 'subdir', 'registry', 'launch', 'timeout_s', 'note', 'added'], what);
  if (typeof t.id !== 'string' || !ID.test(t.id)) fail(`${what}.id must look like s001`);
  if (typeof t.repo !== 'string' || !REPO.test(t.repo) || /\.git$/.test(t.repo)) fail(`${t.id}: repo must be owner/name on GitHub`);
  if ((t.commit === undefined) === (t.ref === undefined)) fail(`${t.id}: set exactly one of commit (a pinned 40-character SHA) or ref (a branch or tag followed at each run)`);
  if (t.commit !== undefined && !(typeof t.commit === 'string' && SHA.test(t.commit))) fail(`${t.id}: commit must be a full 40-character SHA`);
  if (t.ref !== undefined && !(typeof t.ref === 'string' && REF.test(t.ref) && !t.ref.includes('..'))) fail(`${t.id}: ref is not a branch or tag name`);
  if (t.subdir !== undefined && !(typeof t.subdir === 'string' && SUBDIR.test(t.subdir))) fail(`${t.id}: subdir must be a relative path inside the repository`);
  if (t.registry !== undefined && !(typeof t.registry === 'string' && REGISTRY_NAME.test(t.registry))) fail(`${t.id}: registry must be an MCP Registry server name (namespace/name)`);
  if (t.launch !== undefined) validateLaunch(t.launch, t.id);
  if (t.timeout_s !== undefined && !(Number.isInteger(t.timeout_s) && t.timeout_s >= 30 && t.timeout_s <= MAX_TIMEOUT_S)) fail(`${t.id}: timeout_s must be a whole number from 30 to ${MAX_TIMEOUT_S}`);
  return t;
}

export function validateList(list) {
  if (!isObj(list) || list.format !== TARGETS_FORMAT) fail(`the list must have format ${TARGETS_FORMAT}`);
  only(list, ['format', 'about', 'defaults', 'targets', 'dropped'], 'list');
  if (list.defaults !== undefined) {
    if (!isObj(list.defaults)) fail('defaults must be an object');
    only(list.defaults, ['timeout_s'], 'defaults');
    const d = list.defaults.timeout_s;
    if (d !== undefined && !(Number.isInteger(d) && d >= 30 && d <= MAX_TIMEOUT_S)) fail(`defaults.timeout_s must be a whole number from 30 to ${MAX_TIMEOUT_S}`);
  }
  if (!Array.isArray(list.targets) || list.targets.length > 5000) fail('targets must be a list (at most 5000)');
  const seen = new Set();
  // An id is never reused: a dropped target keeps its id in dropped[] so old records stay unambiguous.
  const dropped = list.dropped ?? [];
  if (!Array.isArray(dropped) || !dropped.every((d) => isObj(d) && typeof d.id === 'string' && ID.test(d.id))) fail('dropped must be a list of { id, ... }');
  for (const d of dropped) { const n = idNumber(d.id); if (seen.has(n)) fail(`${d.id} appears twice in dropped`); seen.add(n); }
  list.targets.forEach((t, i) => {
    validateTarget(t, i);
    const n = idNumber(t.id);
    if (seen.has(n)) fail(`${t.id} is used twice (or is a dropped id)`);
    seen.add(n);
  });
  return list;
}

/** Compared by number: s009 and s0009 are the same id. */
export const idNumber = (id) => Number(id.slice(1));

/** Targets in id order; shard k of n takes every n-th, so a list that grows keeps old targets in place. */
export function shardTargets(targets, shard, shards, onlyIds = null) {
  const sorted = [...targets].sort((a, b) => idNumber(a.id) - idNumber(b.id));
  const wanted = onlyIds ? new Set(onlyIds.map(idNumber)) : null;
  const pool = wanted ? sorted.filter((t) => wanted.has(idNumber(t.id))) : sorted;
  return pool.filter((_, i) => i % shards === shard - 1);
}

export const timeoutOf = (t, list) => t.timeout_s ?? list?.defaults?.timeout_s ?? DEFAULT_TIMEOUT_S;

/** In-container paths. /work is the target's own volume (read-write at install, read-only at run). */
export const P = { work: '/work', tools: '/opt/surface', home: '/tmp/home', ca: '/opt/surface-ca/ca.pem' };

/**
 * What to run for one launch block: the image key (images.json), the install steps (with egress,
 * through the allowlist proxy), the lock files to bring back, and the server command (no network).
 * `resolved` carries the versions the install step reported for "latest".
 */
export function launchPlan(l) {
  const args = l.args ?? [];
  if (l.kind === 'npm') {
    const spec = `${l.package}@${l.version}`;
    const bin = l.bin ?? null;
    return {
      image: l.node === '22' ? 'node22' : 'node24',
      registries: ['registry.npmjs.org'],
      install: [
        { name: 'install', cmd: ['npm', 'install', '--prefix', `${P.work}/pkg`, '--no-audit', '--no-fund', '--loglevel=error', '--omit=dev', ...(l.install_scripts ? [] : ['--ignore-scripts']), spec] },
        // The bin the package declares (or the one the list names), resolved by our helper, never by a shell.
        { name: 'entry', cmd: ['node', `${P.tools}/sandbox/npm-entry.mjs`, `${P.work}/pkg`, l.package, bin ?? ''], out: 'entry.json' },
      ],
      locks: [{ path: `${P.work}/pkg/package-lock.json`, name: 'package-lock.json' }],
      // The entry helper printed { script, version }; the server is node <script> <args>.
      run: (entry) => ['node', entry.script, ...args],
    };
  }
  if (l.kind === 'pypi') {
    const spec = l.version === 'latest' ? l.package : `${l.package}==${l.version}`;
    const entry = l.entry ?? l.package;
    return {
      image: 'python',
      registries: ['pypi.org', 'files.pythonhosted.org'],
      install: [
        { name: 'venv', cmd: ['python', '-m', 'venv', `${P.work}/venv`] },
        { name: 'install', cmd: [`${P.work}/venv/bin/python`, '-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', '--no-warn-script-location', spec] },
        { name: 'freeze', cmd: ['sh', '-c', 'mkdir -p /work/lock && /work/venv/bin/python -m pip freeze --all > /work/lock/freeze.txt'] },
      ],
      locks: [{ path: `${P.work}/lock/freeze.txt`, name: 'freeze.txt' }],
      run: () => [`${P.work}/venv/bin/${entry}`, ...args],
    };
  }
  if (l.kind === 'go') {
    const base = l.module.split('/').filter((x) => !/^v[0-9]+$/.test(x)).pop();
    return {
      image: 'go',
      registries: ['proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com'],
      install: [
        { name: 'install', cmd: ['go', 'install', `${l.module}@${l.version}`], env: { GOBIN: `${P.work}/bin`, GOPATH: `${P.work}/go`, GOCACHE: `${P.work}/gocache`, GOFLAGS: '-mod=mod', CGO_ENABLED: '0', GOTOOLCHAIN: 'local', GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org' } },
        { name: 'buildinfo', cmd: ['sh', '-c', `mkdir -p /work/lock && go version -m "/work/bin/$1" > /work/lock/go-version-m.txt`, 'sh', base] },
      ],
      locks: [{ path: `${P.work}/lock/go-version-m.txt`, name: 'go-version-m.txt' }],
      // A static binary (CGO_ENABLED=0): it runs in the node image, which has no Go toolchain.
      runImage: 'node24',
      run: () => [`${P.work}/bin/${base}`, ...args],
    };
  }
  // docker: the target's own image is the sandbox; nothing is installed.
  return { image: null, targetImage: l.image, registries: [], install: [], locks: [], run: () => [...args], entrypoint: l.entrypoint ?? null };
}
