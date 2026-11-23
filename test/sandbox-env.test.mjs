import test from 'node:test';
import assert from 'node:assert/strict';
import { ENV_DENY, envNameAllowed, hostSecretValues, targetEnvProblems, settingsManifest, settingsDigest, canonical, inspectMismatches, parseMemory } from '../src/sandbox-env.mjs';
import { sandboxRunArgs, helperRunArgs } from '../src/docker.mjs';
import { envPlan } from '../bin/run-shard.mjs';

const IMG = `docker.io/library/python:3.13-slim-bookworm@sha256:${'e'.repeat(64)}`;
const argv = (o = {}) => sandboxRunArgs({ name: 'surface-x-case1', image: IMG, network: 'surface-x-run', ip: '10.213.53.3', resolv: 'run', mounts: [{ src: 'surface-x-work', dst: '/work' }], env: { HOME: '/tmp/home', B: '2', A: '1' }, cmd: ['python3', '/opt/surface/selftest/hostile.py', 'env-token'], cidfile: '/tmp/c/cid', detach: true, hostEnv: {}, ...o });

test('names a target never gets, and the ones it may', () => {
  for (const n of ['GITHUB_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'RUNNER_TOOL_CACHE', 'GH_TOKEN', 'INPUT_TOKEN', 'CORPUS_TARGETS_KEY', 'SURFACE_IMAGE_MIRROR', 'LD_PRELOAD', 'DOCKER_CONFIG', 'GIT_ASKPASS', 'SSH_AUTH_SOCK', 'BASH_ENV']) assert.ok(!envNameAllowed(n), n);
  for (const n of ['HOME', 'SURFACE_SANDBOX', 'API_KEY', 'GITLAB_TOKEN', 'OPENWEATHER_API_KEY', 'npm_config_cache', 'GITEA_HOST']) assert.ok(envNameAllowed(n), n);
  assert.ok(ENV_DENY.test('github_token'), 'case does not matter');
});

test('host secrets: only secret-named variables of 8 characters or more count', () => {
  const v = hostSecretValues({ GH_TOKEN: 'ghs_abcdefgh', ACTIONS_RUNTIME_TOKEN: 'eyJ0eXAiOiJKV1Qi', RUNNER_TEMP: '/home/runner/work/_temp', CORPUS_TARGETS_KEY: 'AGE-SECRET-KEY-1XYZ', SHORT_TOKEN: 'abc', PATH: '/usr/bin:/bin' });
  assert.deepEqual(v.sort(), ['AGE-SECRET-KEY-1XYZ', 'eyJ0eXAiOiJKV1Qi', 'ghs_abcdefgh']);
  assert.deepEqual(targetEnvProblems({ X: 'eyJ0eXAiOiJKV1Qi' }, { ACTIONS_RUNTIME_TOKEN: 'eyJ0eXAiOiJKV1Qi' }), ['X holds a value the host keeps under a secret name']);
  assert.deepEqual(targetEnvProblems({ HOME: '/tmp/home' }, { ACTIONS_RUNTIME_TOKEN: 'eyJ0eXAiOiJKV1Qi' }), []);
});

test('the env plan never offers a name the sandbox refuses (it is recorded, not set)', () => {
  const p = envPlan({ kind: 'npm', package: 'x', env: { GH_TOKEN: 'v', SSH_PRIVATE_KEY: 'k', API_KEY: 'k' } }, null, null);
  assert.deepEqual(Object.keys(p.env), ['API_KEY']);
  assert.deepEqual(p.names.list, ['GH_TOKEN', 'SSH_PRIVATE_KEY', 'API_KEY']);
  assert.deepEqual(targetEnvProblems(p.env, {}), []);
});

test('the settings manifest is read back from the exact run arguments', () => {
  const m = settingsManifest(argv(), { role: 'case' });
  assert.equal(m.role, 'case');
  assert.equal(m.runtime, 'runsc');
  assert.equal(m.user, '65534:65534');
  assert.deepEqual(m.cap_drop, ['ALL']);
  assert.deepEqual(m.cap_add, []);
  assert.deepEqual(m.security_opt, ['no-new-privileges']);
  assert.equal(m.read_only, true);
  assert.equal(m.pids_limit, 2048);
  assert.equal(m.memory, '2g');
  assert.equal(m.network, 'surface-x-run');
  assert.equal(m.ip, '10.213.53.3');
  assert.deepEqual(m.mounts, [
    { type: 'bind', src: '/etc/isokron-sandbox/resolv-run.conf', dst: '/etc/resolv.conf', ro: true },
    { type: 'volume', src: 'surface-x-work', dst: '/work', ro: false },
  ]);
  assert.deepEqual(m.env_names, ['A', 'B', 'HOME']);
  assert.equal(m.image, IMG);
  assert.equal(m.cmd_argc, 3);
  assert.ok(!JSON.stringify(m).includes('/tmp/home'), 'env values are a digest only');
  assert.match(settingsDigest(m), /^[0-9a-f]{64}$/);
});

test('the digest is stable for equal settings and changes with any of them', () => {
  const a = settingsManifest(argv());
  const b = settingsManifest(argv({ env: { A: '1', HOME: '/tmp/home', B: '2' } }));
  assert.equal(settingsDigest(a), settingsDigest(b), 'env order does not matter');
  assert.notEqual(settingsDigest(a), settingsDigest(settingsManifest(argv({ env: { A: '1', HOME: '/tmp/home', B: '3' } }))));
  assert.notEqual(settingsDigest(a), settingsDigest(settingsManifest(argv({ cpus: 1 }))));
  assert.equal(canonical({ b: [1, { d: 1, c: 2 }], a: null }), '{"a":null,"b":[1,{"c":2,"d":1}]}');
});

test('a helper manifest shows its runtime and its one capability', () => {
  const m = settingsManifest(helperRunArgs({ name: 'n', image: IMG, user: '0:0', capAdd: ['NET_BIND_SERVICE'], network: 'surface-x-run', ip: '10.213.53.2', cmd: ['node', 'netlog.mjs'] }));
  assert.equal(m.runtime, 'runsc');
  assert.deepEqual(m.cap_add, ['NET_BIND_SERVICE']);
  assert.equal(m.pids_limit, 256);
  assert.deepEqual(m.hosts, []);
  const p = settingsManifest(helperRunArgs({ name: 'n', image: IMG, network: 'surface-x-run', ip: '10.213.53.4', hosts: [['server', '10.213.53.3']], cmd: ['node', 'probe.mjs'] }));
  assert.deepEqual(p.hosts, ['server:10.213.53.3'], 'a fixed host entry is a setting');
  assert.equal(p.image, IMG);
});

const inspectOf = (m, over = {}) => ({
  HostConfig: { Runtime: 'runsc', CapDrop: ['ALL'], CapAdd: null, Privileged: false, SecurityOpt: ['no-new-privileges'], ReadonlyRootfs: true, PidsLimit: 2048, Ulimits: [{ Name: 'nofile', Soft: 4096, Hard: 4096 }, { Name: 'nproc', Soft: 512, Hard: 512 }], Memory: 2 * 1024 ** 3, NanoCpus: 2e9, NetworkMode: m.network, PidMode: '', IpcMode: 'private', Devices: [], Binds: null, ...(over.HostConfig || {}) },
  Config: { User: '65534:65534', Env: ['PATH=/usr/local/bin:/usr/bin', 'HOME=/tmp/home', 'A=1', 'B=2', 'PYTHON_VERSION=3.13.1'], ...(over.Config || {}) },
  Mounts: over.Mounts ?? [
    { Type: 'bind', Source: '/etc/isokron-sandbox/resolv-run.conf', Destination: '/etc/resolv.conf', RW: false },
    { Type: 'volume', Name: 'surface-x-work', Destination: '/work', RW: true },
  ],
});

test('inspect: a container that matches its manifest has no mismatch; each drift is named', () => {
  const m = settingsManifest(argv());
  assert.deepEqual(inspectMismatches(inspectOf(m), m), []);
  const drift = (over) => inspectMismatches(inspectOf(m, over), m);
  assert.match(drift({ HostConfig: { Runtime: 'runc' } }).join(), /runtime is runc/);
  assert.match(drift({ Config: { User: '0:0' } }).join(), /user is 0:0/);
  assert.match(drift({ HostConfig: { CapAdd: ['NET_RAW'] } }).join(), /capabilities added: NET_RAW/);
  assert.match(drift({ HostConfig: { ReadonlyRootfs: false } }).join(), /read-only/);
  assert.match(drift({ HostConfig: { SecurityOpt: [] } }).join(), /no-new-privileges/);
  assert.match(drift({ HostConfig: { PidsLimit: 0 } }).join(), /pids limit/);
  assert.match(drift({ HostConfig: { Ulimits: [{ Name: 'nofile', Soft: 4096, Hard: 4096 }] } }).join(), /ulimit nproc is not 512:512/);
  assert.match(drift({ HostConfig: { Privileged: true } }).join(), /privileged/);
  assert.match(drift({ HostConfig: { ExtraHosts: ['host.internal:host-gateway'] } }).join(), /host entries/);
  assert.match(drift({ HostConfig: { PidMode: 'host' } }).join(), /host namespace/);
  assert.match(drift({ Mounts: [{ Type: 'bind', Source: '/home/runner/work', Destination: '/work', RW: true }] }).join(), /unexpected mount at \/work/);
  assert.match(drift({ Mounts: [{ Type: 'bind', Source: '/var/run/x.sock', Destination: '/var/run/x.sock', RW: false }] }).join(), /unexpected mount/);
  assert.match(drift({ Config: { Env: ['HOME=/tmp/home', 'A=1', 'B=2', 'GITHUB_TOKEN=x'] } }).join(), /environment has GITHUB_TOKEN/);
  assert.match(drift({ Config: { Env: ['HOME=/tmp/home', 'A=1'] } }).join(), /environment lacks B/);
  assert.match(inspectMismatches(inspectOf(m, { Config: { Env: ['HOME=/tmp/home', 'A=1', 'B=canary-123456'] } }), m, { canaries: ['canary-123456'] }).join(), /canary/);
});

test('memory sizes', () => {
  assert.equal(parseMemory('2g'), 2147483648);
  assert.equal(parseMemory('256m'), 268435456);
  assert.equal(parseMemory('x'), null);
});
