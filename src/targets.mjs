// The target list (format isokron-surface-targets/1): validation, sharding and the launch plan.
// The real list is never in the repository in clear text (targets/targets.json.age); the public
// example (targets/example.targets.json) names three reference servers and has the same format.
// targets/FORMAT.md documents every field.

export const TARGETS_FORMAT = 'isokron-surface-targets/1';
export const ID = /^s[0-9]{3,4}$/;
export const MAX_TIMEOUT_S = 1800;
export const DEFAULT_TIMEOUT_S = 600;
export const KINDS = ['npm', 'pypi', 'go', 'docker', 'cargo', 'nuget', 'mcpb'];
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
// A crate name (crates.io: letters, digits, - and _, at most 64) and an exact crate version.
export const CRATE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const CRATE_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,60})?$/;
// A NuGet package id (never starting with - or .) and an exact NuGet version (SemVer 2, or a four-part version).
export const NUGET_ID = /^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?$/;
const NUGET_VERSION = /^[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]{1,60})?(?:\+[0-9A-Za-z.-]{1,60})?$/;
// An MCP Bundle (.mcpb) is fetched from a GitHub release asset only: the URL as the registry lists it, on github.com,
// which redirects to its release-asset hosts. Those three hosts are the install's whole allowlist (plus PyPI for a
// bundle of server type uv).
export const MCPB_URL = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}\/releases\/download\/[A-Za-z0-9._+@-]{1,128}\/[A-Za-z0-9._+@-]{1,200}$/;
export const MCPB_HOSTS = Object.freeze(['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']);
export const MCPB_RUNTIMES = ['node', 'python', 'binary', 'uv'];
/** The most an MCP bundle may weigh as downloaded (sandbox/mcpb-fetch.mjs refuses more). */
export const MCPB_MAX_BYTES = 200 * 1024 * 1024;
// A path inside a bundle: relative, no . or .. segment, no backslash.
const BUNDLE_PATH = /^(?![/.])(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._@+ /-]{1,300}$/;
const IMAGE = /^[a-z0-9][a-z0-9./_-]{0,200}(?::[A-Za-z0-9._-]{1,120})?@sha256:[0-9a-f]{64}$/;
// A version constraint on a dependency of a pypi target: name, optional comparison(s). No extras, markers, URLs or paths.
const PIP_CONSTRAINT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,80}[A-Za-z0-9])?(?:(?:==|!=|<=|>=|~=|<|>)[0-9][0-9A-Za-z.*+!-]{0,40})(?:,(?:==|!=|<=|>=|~=|<|>)[0-9][0-9A-Za-z.*+!-]{0,40}){0,3}$/;
// An extra of a pypi target (PEP 685 normalised: lower case, - for runs of -_.).
const PIP_EXTRA = /^[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?$/;
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
    only(l, [...common, 'package', 'version', 'entry', 'constraints', 'extras'], `${what}.launch`);
    if (typeof l.package !== 'string' || !PYPI_NAME.test(l.package)) fail(`${what}.launch.package is not a PyPI project name`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && SEMVER.test(l.version)))) fail(`${what}.launch.version must be an exact version or "latest"`);
    if (l.entry !== undefined && !(typeof l.entry === 'string' && BIN.test(l.entry))) fail(`${what}.launch.entry is not a console-script name`);
    if (l.extras !== undefined && !(Array.isArray(l.extras) && l.extras.length >= 1 && l.extras.length <= 4 && l.extras.every((x) => typeof x === 'string' && PIP_EXTRA.test(x)) && new Set(l.extras).size === l.extras.length)) fail(`${what}.launch.extras must be one to four extra names such as "mcp"`);
    if (l.constraints !== undefined && !(Array.isArray(l.constraints) && l.constraints.length <= 10 && l.constraints.every((c) => typeof c === 'string' && PIP_CONSTRAINT.test(c)))) fail(`${what}.launch.constraints must be at most 10 version constraints such as "mcp<2"`);
  } else if (l.kind === 'go') {
    only(l, [...common, 'module', 'version'], `${what}.launch`);
    if (typeof l.module !== 'string' || !GO_MODULE.test(l.module)) fail(`${what}.launch.module is not a Go package path`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && GO_VERSION.test(l.version)))) fail(`${what}.launch.version must be vX.Y.Z, a commit, or "latest"`);
  } else if (l.kind === 'cargo') {
    only(l, [...common, 'crate', 'version'], `${what}.launch`);
    if (typeof l.crate !== 'string' || !CRATE.test(l.crate)) fail(`${what}.launch.crate is not a crate name`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && CRATE_VERSION.test(l.version)))) fail(`${what}.launch.version must be an exact crate version or "latest"`);
  } else if (l.kind === 'nuget') {
    only(l, [...common, 'package', 'version'], `${what}.launch`);
    if (typeof l.package !== 'string' || !NUGET_ID.test(l.package)) fail(`${what}.launch.package is not a NuGet package id`);
    if (!(l.version === 'latest' || (typeof l.version === 'string' && NUGET_VERSION.test(l.version)))) fail(`${what}.launch.version must be an exact NuGet version or "latest"`);
  } else if (l.kind === 'mcpb') {
    only(l, [...common, 'url', 'sha256', 'runtime', 'entry', 'pythonpath', 'console', 'extras', 'workdir'], `${what}.launch`);
    if (typeof l.url !== 'string' || !MCPB_URL.test(l.url)) fail(`${what}.launch.url must be a GitHub release asset (https://github.com/<owner>/<repo>/releases/download/<tag>/<file>)`);
    if (typeof l.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(l.sha256)) fail(`${what}.launch.sha256 must be the bundle's sha256 (64 hex digits)`);
    if (!MCPB_RUNTIMES.includes(l.runtime)) fail(`${what}.launch.runtime must be one of ${MCPB_RUNTIMES.join(', ')}`);
    if (l.runtime === 'binary') { if (typeof l.entry !== 'string' || !BUNDLE_PATH.test(l.entry)) fail(`${what}.launch.entry must be the binary's path inside the bundle`); } else if (l.entry !== undefined) fail(`${what}.launch.entry is for a binary bundle only`);
    if (l.pythonpath !== undefined && !(['python', 'uv'].includes(l.runtime) && Array.isArray(l.pythonpath) && l.pythonpath.length <= 8 && l.pythonpath.every((x) => x === '.' || (typeof x === 'string' && BUNDLE_PATH.test(x))))) fail(`${what}.launch.pythonpath must be at most 8 paths inside the bundle, for a python or uv bundle`);
    if (l.console !== undefined && !(l.runtime === 'uv' && typeof l.console === 'string' && BIN.test(l.console))) fail(`${what}.launch.console is a console-script name, for a uv bundle only`);
    if (l.extras !== undefined && !(l.runtime === 'uv' && Array.isArray(l.extras) && l.extras.length <= 8 && l.extras.every((x) => typeof x === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$/.test(x)))) fail(`${what}.launch.extras must be at most 8 extra names, for a uv bundle only`);
    if (l.workdir !== undefined && !(l.workdir === '.' || (typeof l.workdir === 'string' && BUNDLE_PATH.test(l.workdir)))) fail(`${what}.launch.workdir must be a folder inside the bundle`);
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

/** The install env of an npm target built from source: the image's own Node headers, no prebuilt downloads. */
export const NATIVE_BUILD_ENV = Object.freeze({ npm_config_nodedir: '/usr/local', npm_config_build_from_source: 'true' });

/** The longest a build step may take (a crate's `cargo install`), and any other package install step. */
export const BUILD_CAP_MS = 15 * 60_000;
export const INSTALL_CAP_MS = 5 * 60_000;

/** The hosts a Go build may reach: the module proxy and the checksum database (R-SBX-62). */
export const GO_REGISTRIES = Object.freeze(['proxy.golang.org', 'sum.golang.org']);

/** A Go install: its folders in the work volume, read-only module files, no VCS stamp, no cgo, no telemetry, the image's own toolchain. */
export const GO_ENV = Object.freeze({ GOBIN: `${P.work}/bin`, GOPATH: `${P.work}/go`, GOCACHE: `${P.work}/gocache`, GOTMPDIR: `${P.work}/gotmp`, GOFLAGS: '-mod=readonly -buildvcs=false', CGO_ENABLED: '0', GOTOOLCHAIN: 'local', GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org', GOTELEMETRY: 'off' });

/** A crate's build: its own folders in the work volume, crates.io's sparse index, two jobs, no colour or progress bars. */
export const CARGO_ENV = Object.freeze({ CARGO_HOME: `${P.work}/cargo-home`, CARGO_TARGET_DIR: `${P.work}/target`, CARGO_TERM_COLOR: 'never', CARGO_TERM_PROGRESS_WHEN: 'never', CARGO_BUILD_JOBS: '2', CARGO_NET_RETRY: '2', CARGO_HTTP_TIMEOUT: '60', CARGO_REGISTRIES_CRATES_IO_PROTOCOL: 'sparse', CARGO_INCREMENTAL: '0' });

/**
 * A .NET tool install: the package cache and the CLI's home in the work volume, no telemetry or first-run work, and
 * certificate revocation checked offline (the install network reaches NuGet's two hosts only).
 */
export const NUGET_ENV = Object.freeze({ NUGET_PACKAGES: `${P.work}/nuget`, DOTNET_CLI_HOME: `${P.work}/home`, DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1', DOTNET_GENERATE_ASPNET_CERTIFICATE: 'false', DOTNET_ADD_GLOBAL_TOOLS_TO_PATH: 'false', NUGET_CERT_REVOCATION_MODE: 'offline', NUGET_XMLDOC_MODE: 'skip' });

/** A .NET tool's run: on the image's runtime (rolled forward from an older target framework), no telemetry, no diagnostics IPC. */
export const DOTNET_RUN_ENV = Object.freeze({ DOTNET_ROLL_FORWARD: 'Major', DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', DOTNET_EnableDiagnostics: '0' });

const bundlePath = (rel) => (rel === '.' ? `${P.work}/pkg` : `${P.work}/pkg/${rel}`);

/**
 * An MCP Bundle (.mcpb): sandbox/mcpb-fetch.mjs, in the node image, downloads the release asset through the proxy
 * (github.com and its two release-asset hosts only), checks its size and its sha256 (the one the list names: the
 * registry's own, or the one the planner read), and unpacks it into /work/pkg with path, link, count and size guards.
 * Nothing of the bundle runs at install, except for a bundle of server type uv: its pyproject's dependencies (or the
 * project itself, when it declares a build system) are installed with pip into a venv through PyPI only, as `uv run`
 * would. The server then runs from the read-only volume, in the image its runtime needs:
 *   node    node <args>                    (node24)
 *   python  python <args>                  (python), PYTHONPATH from the manifest, inside the bundle only
 *   uv      <venv>/bin/python <args>, or <venv>/bin/<console> <args>    (python)
 *   binary  /work/pkg/<entry> <args>       (node24-build: the full Debian image, for the libraries a binary links)
 */
function mcpbPlan(l, args) {
  const fetch = { name: 'fetch', image: 'node24', capMs: INSTALL_CAP_MS, cmd: ['node', `${P.tools}/sandbox/mcpb-fetch.mjs`, l.url, l.sha256, `${P.work}/pkg`, ...(l.runtime === 'binary' ? ['--exec', l.entry] : [])], out: 'fetch.json' };
  const pythonpath = l.pythonpath && l.pythonpath.length ? { PYTHONPATH: l.pythonpath.map(bundlePath).join(':') } : {};
  const workdir = l.workdir ? bundlePath(l.workdir) : null;
  const common = { locks: [{ path: `${P.work}/pkg/manifest.json`, name: 'mcpb-manifest.json' }], ...(workdir ? { workdir } : {}) };
  if (l.runtime === 'uv') {
    return {
      ...common,
      image: 'python',
      registries: [...MCPB_HOSTS, 'pypi.org', 'files.pythonhosted.org'],
      install: [
        fetch,
        { name: 'venv', cmd: ['python', '-m', 'venv', `${P.work}/venv`] },
        { name: 'requirements', cmd: ['python', '-I', `${P.tools}/sandbox/pyproject-reqs.py`, `${P.work}/pkg`, `${P.work}/lock/requirements.txt`, ...(l.extras ?? [])], out: 'requirements.json' },
        { name: 'install', capMs: INSTALL_CAP_MS, cmd: [`${P.work}/venv/bin/python`, '-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', '--no-warn-script-location', '-r', `${P.work}/lock/requirements.txt`] },
        { name: 'freeze', cmd: ['sh', '-c', '/work/venv/bin/python -m pip freeze --all > /work/lock/freeze.txt'] },
      ],
      locks: [...common.locks, { path: `${P.work}/lock/freeze.txt`, name: 'freeze.txt' }],
      runEnv: pythonpath,
      run: () => [l.console ? `${P.work}/venv/bin/${l.console}` : `${P.work}/venv/bin/python`, ...args],
    };
  }
  if (l.runtime === 'python') return { ...common, image: 'node24', runImage: 'python', registries: [...MCPB_HOSTS], install: [fetch], runEnv: pythonpath, run: () => ['python', ...args] };
  if (l.runtime === 'binary') return { ...common, image: 'node24', runImage: 'node24-build', registries: [...MCPB_HOSTS], install: [fetch], run: () => [bundlePath(l.entry), ...args] };
  return { ...common, image: 'node24', runImage: 'node24', registries: [...MCPB_HOSTS], install: [fetch], run: () => ['node', ...args] };
}

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
    const node = l.node === '22' ? 'node22' : 'node24';
    // With install scripts on, a native module may compile: the install runs in the full image of
    // the same Node release (compilers, make, python3, the Node headers in /usr/local), built from
    // source against those headers. Prebuilt binaries are not fetched (their hosts are not on the
    // allowlist, and npm's registry is the only door). The server runs in the slim image as always.
    const build = l.install_scripts === true;
    return {
      image: build ? `${node}-build` : node,
      ...(build ? { runImage: node } : {}),
      registries: ['registry.npmjs.org'],
      install: [
        { name: 'install', cmd: ['npm', 'install', '--prefix', `${P.work}/pkg`, '--no-audit', '--no-fund', '--loglevel=error', '--omit=dev', ...(l.install_scripts ? [] : ['--ignore-scripts']), spec], ...(build ? { env: NATIVE_BUILD_ENV } : {}) },
        // The bin the package declares (or the one the list names), resolved by our helper, never by a shell.
        { name: 'entry', cmd: ['node', `${P.tools}/sandbox/npm-entry.mjs`, `${P.work}/pkg`, l.package, bin ?? ''], out: 'entry.json' },
      ],
      locks: [{ path: `${P.work}/pkg/package-lock.json`, name: 'package-lock.json' }],
      // The entry helper printed { script, version }; the server is node <script> <args>.
      run: (entry) => ['node', entry.script, ...args],
    };
  }
  if (l.kind === 'pypi') {
    // The extras the planner chose (the one holding the MCP server: mcp, server, cli) install with the package.
    const name = l.extras ? `${l.package}[${l.extras.join(',')}]` : l.package;
    const spec = l.version === 'latest' ? name : `${name}==${l.version}`;
    const entry = l.entry ?? l.package;
    return {
      image: 'python',
      registries: ['pypi.org', 'files.pythonhosted.org'],
      install: [
        { name: 'venv', cmd: ['python', '-m', 'venv', `${P.work}/venv`] },
        { name: 'install', cmd: [`${P.work}/venv/bin/python`, '-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', '--no-warn-script-location', spec, ...(l.constraints ?? [])] },
        { name: 'freeze', cmd: ['sh', '-c', 'mkdir -p /work/lock && /work/venv/bin/python -m pip freeze --all > /work/lock/freeze.txt'] },
      ],
      locks: [{ path: `${P.work}/lock/freeze.txt`, name: 'freeze.txt' }],
      run: () => [`${P.work}/venv/bin/${entry}`, ...args],
    };
  }
  if (l.kind === 'go') {
    // `go install <package path>@<version>` in the pinned Go image (images.json), at most BUILD_CAP_MS. The version is a
    // release tag or a full commit; a commit is how a repository with no release is built at the commit it was read at.
    // The module proxy and the checksum database are the only doors (R-SBX-62); a module that needs another host fails
    // as a denied host, which the harness tells apart from a failure of the package. Read-only module files (-mod=readonly),
    // no VCS stamp (the image has no git), the toolchain the image has (GOTOOLCHAIN=local), no cgo, and Go's own
    // scratch folder in the work volume (the sandbox's /tmp is small). The module cache and the build cache are removed
    // after the build, so what the server's container mounts is the binary and the build record.
    const base = l.module.split('/').filter((x) => !/^v[0-9]+$/.test(x)).pop();
    return {
      image: 'go',
      registries: [...GO_REGISTRIES],
      install: [
        { name: 'prep', cmd: ['mkdir', '-p', `${P.work}/gotmp`] },
        { name: 'install', capMs: BUILD_CAP_MS, cmd: ['go', 'install', `${l.module}@${l.version}`], env: GO_ENV },
        { name: 'buildinfo', cmd: ['sh', '-c', `mkdir -p /work/lock && go version -m "/work/bin/$1" > /work/lock/go-version-m.txt`, 'sh', base] },
        { name: 'clean', cmd: ['sh', '-c', 'chmod -R u+w /work/go /work/gocache /work/gotmp 2>/dev/null; rm -rf /work/go /work/gocache /work/gotmp'] },
      ],
      locks: [{ path: `${P.work}/lock/go-version-m.txt`, name: 'go-version-m.txt' }],
      // A static binary (CGO_ENABLED=0): it runs in the node image, which has no Go toolchain.
      runImage: 'node24',
      run: () => [`${P.work}/bin/${base}`, ...args],
    };
  }
  if (l.kind === 'cargo') {
    // `cargo install --locked` (the Cargo.lock the crate published, when it published one) in the pinned Rust image,
    // through crates.io's sparse index and its download host only; `--` ends the options before the checked name. The
    // binary is the one cargo recorded (sandbox/cargo-entry.mjs, in the node image); the build's folders (target,
    // cargo home) are removed before the server starts, so what is left of the build in the volume its container mounts
    // is the install root (the binary and cargo's install records). It
    // runs in the same Rust image, which has the libraries it linked against. The build may take BUILD_CAP_MS.
    return {
      image: 'rust-build',
      runImage: 'rust-build',
      registries: ['index.crates.io', 'static.crates.io'],
      install: [
        { name: 'install', capMs: BUILD_CAP_MS, cmd: ['cargo', 'install', '--locked', '--root', `${P.work}/pkg`, ...(l.version === 'latest' ? [] : ['--version', l.version]), '--', l.crate], env: CARGO_ENV },
        { name: 'entry', image: 'node24', cmd: ['node', `${P.tools}/sandbox/cargo-entry.mjs`, `${P.work}/pkg`, l.crate], out: 'entry.json' },
        { name: 'clean', cmd: ['rm', '-rf', `${P.work}/target`, `${P.work}/cargo-home`] },
      ],
      locks: [{ path: `${P.work}/pkg/.crates2.json`, name: 'crates2.json' }],
      run: (entry) => [entry.script, ...args],
    };
  }
  if (l.kind === 'nuget') {
    // A .NET tool package: `dotnet tool install --tool-path` in the pinned .NET SDK image, with a NuGet config of ours
    // that names nuget.org alone, through api.nuget.org and globalcdn.nuget.org only. The command is the one the
    // package's DotnetToolSettings.xml declares (sandbox/nuget-entry.mjs, in the node image); the package cache is
    // removed before the server starts. It runs on the image's .NET runtime, rolled forward to it when the tool was
    // built for an older one.
    return {
      image: 'dotnet-sdk',
      runImage: 'dotnet-sdk',
      registries: ['api.nuget.org', 'globalcdn.nuget.org'],
      install: [
        { name: 'config', cmd: ['sh', '-c', 'printf \'%s\\n\' \'<?xml version="1.0" encoding="utf-8"?>\' \'<configuration><packageSources><clear /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" /></packageSources></configuration>\' > /work/nuget.config'] },
        { name: 'install', capMs: INSTALL_CAP_MS, cmd: ['dotnet', 'tool', 'install', l.package, '--tool-path', `${P.work}/pkg`, '--configfile', `${P.work}/nuget.config`, '--allow-roll-forward', ...(l.version === 'latest' ? [] : ['--version', l.version])], env: NUGET_ENV },
        { name: 'entry', image: 'node24', cmd: ['node', `${P.tools}/sandbox/nuget-entry.mjs`, `${P.work}/pkg`, l.package], out: 'entry.json' },
        { name: 'clean', cmd: ['rm', '-rf', `${P.work}/nuget`, `${P.work}/home/.nuget`, `${P.work}/home/.dotnet`, `${P.work}/home/.local`] },
      ],
      locks: [],
      runEnv: DOTNET_RUN_ENV,
      run: (entry) => (entry.runner === 'dotnet' ? ['dotnet', entry.script, ...args] : [entry.script, ...args]),
    };
  }
  if (l.kind === 'mcpb') return mcpbPlan(l, args);
  // docker: the target's own image is the sandbox; nothing is installed.
  return { image: null, targetImage: l.image, registries: [], install: [], locks: [], run: () => [...args], entrypoint: l.entrypoint ?? null };
}
