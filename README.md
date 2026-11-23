# MCP surface corpus

Runs IsoKron's free MCP checker (the engine of [isokron.ai/mcp-check](https://isokron.ai/mcp-check)
and [`@isokron/mcp-check`](https://github.com/isokron-ai/mcp-check), rubric 2.1.0, 76 checks) over the
real tool lists of open-source MCP servers on GitHub, nightly, to calibrate and improve the checker.

It is calibration data, not a findings channel. Which servers are in the corpus is not public; only
aggregate counts are (cells under 5 servers withheld). [SECURITY.md](SECURITY.md) has the model.

## How a target is read

Each target is acquired through every layer that works, and the record says which ones did:

| Layer | What | Where it runs |
|---|---|---|
| (a) registry | The official MCP Registry entry: packages, remotes, declared env vars (and a tool list when it has one) | host fetch, JSON only |
| (b) live | Install the package in a sandbox container, start the server (stdio or local HTTP), send `initialize`, `tools/list` (every page), `prompts/list`, `resources/list`, `resources/templates/list`. Twice when the server reads env: once with none, once with dummy values. No tool is ever called. | sandbox containers under gVisor; at run time an internal network with only our probe and network logger |
| (c) static | Tool registrations read from the source of the pinned commit (TypeScript/JavaScript and Python SDK calls via the checker's own `--repo` reader, Go `mcp-go` / official Go SDK calls) | helper container under gVisor, no network |
| (d) readme | Tool names from the README | helper container under gVisor, no network |

The checker engine then grades every list it got (live, best static, README, registry) and the
record compares them.

## The sandbox

Every container that runs target code runs under gVisor (`runsc`; release and sha512 pinned in
`gvisor.json`, installed by `scripts/install-runsc.sh`, syscall tracing on) as user 65534 with no
capabilities, a read-only root and memory, pid and CPU limits. Its network is `--internal`: every
name resolves to our network logger (a DNS sinkhole that logs each query and connection attempt),
installs reach their package registry only through an allowlist proxy, and `scripts/net-guard.sh`
logs and drops anything that tries to leave, IPv6 included. Before any target the driver checks that
the daemon's runsc has exactly the pinned flags and runs a smoke container under it; if anything is
missing it records a `skip` and stops: nothing falls back to runc. Each run writes telemetry
(settings, containers, syscall trace summaries, DNS queries, connections, egress, firewall drops;
[docs/TELEMETRY.md](docs/TELEMETRY.md)). `sandbox-selftest.yml` runs a hostile target through eleven
escape attempts and passes only when every one was blocked and logged. [SECURITY.md](SECURITY.md)
has the details.

## What is captured per target (encrypted)

- Raw JSON-RPC transcripts of every probe; `serverInfo`, `protocolVersion`, capabilities,
  `listChanged`, instructions length, notifications and server-to-client requests seen.
- Transport, startup time (net of an empty server's baseline), time to `tools/list`, pages and
  whether the list is paginated, counts of prompts, resources and resource templates, and whether
  each advertised capability answered.
- Env vars: declared in the registry (required, secret), named in the README, read in source,
  used; whether the server starts with no env and with dummy env, and whether env changes the list.
- List size in bytes and estimated tokens (bytes/4, a BPE approximation, a Claude approximation).
- SDK and version from the installed lock (`package-lock.json`, `pip freeze`, `go version -m`) or the
  source manifests; primary language; licence, stars, forks, archived, last commit date, pinned SHA.
- Full checker output for each list: every check, every finding with its evidence, grades per
  scorecard; annotation coverage, output schemas, description and schema features.
- Static vs live: tool names only in one list, per-tool agreement of description, schema and
  parameters, and which checks disagree.
- Per-tool fingerprints, and the diff against the previous run (tools added, removed or changed by
  part; checks newly firing or cleared; grade, SDK, protocol and version changes).
- Install and run logs, the egress proxy's log of every host the install contacted.
- The sandbox telemetry of the target's containers ([docs/TELEMETRY.md](docs/TELEMETRY.md)): the
  settings and their digest, the runtime, syscall trace summaries, DNS queries and connection
  attempts seen by the network logger, the proxy's requests and the host firewall's drops.

## Outputs of a run

| Artifact | Contents | Readable by |
|---|---|---|
| `surface-shard-N` | `surface-shard-N.tgz.age` (everything above), `surface-shard-N-rows.tgz.age` | archive key (rows also CI key) |
| `surface-aggregate` | `aggregate.json`, `calibration.md` | public |
| `surface-aggregate-private` | exact aggregate, calibration report with target ids, diffs | archive key |
| `surface-state` | fingerprints for the next run's diff | archive key + CI key |

`calibration.md` lists checks that fire on almost every server (at least 90%), checks that never
fire, prevalence of each check, and checks whose static and live results disagree on at least 20% of
servers. [`examples/reference-run/`](examples/reference-run/) is the output of the public example.

## Workflows

- `ci.yml` (pull requests, pushes to `main`): unit tests on Node 22 and 24, engine hashes,
  shellcheck; then gVisor and the network guard, the sandbox tests against the runner's Docker and
  the whole pipeline end to end on the public example list (`targets/example.targets.json`: three
  reference servers from `modelcontextprotocol/servers`). No secret. `ci-ok` is the one required
  status check.
- `corpus.yml` (nightly 07:17 UTC and `workflow_dispatch` with optional `only` ids and `shards`):
  plan, a matrix of up to 16 shard jobs (8 for the whole list, never more than `LOOP_SLOTS`), one
  aggregate job. One run at a time.
- `sandbox-selftest.yml` (`workflow_dispatch`, and pull requests that touch the sandbox or anything
  the self test imports): installs gVisor, guards the networks, runs `bin/sandbox-selftest.mjs` and
  checks its telemetry with `scripts/check-selftest.mjs`; uploads the telemetry and `results.json`.
  No secret.

All three run on GitHub's free hosted runners in a public repository. `corpus.yml`, and
`sandbox-selftest.yml` when run by hand, start with the loop guard: they do nothing (a notice, not a
failure) unless the repository variable `LOOP_ENABLED` is exactly `true` and `LOOP_SLOTS` is a whole
number from 1 to 999. A pull request's self test does not depend on them.

## Running it locally

```sh
npm test                                     # unit tests (Docker tests: SURFACE_DOCKER_TESTS=1)
sudo scripts/install-runsc.sh "$(command -v node)"   # gVisor, registered as Docker's runtime runsc
sudo scripts/net-guard.sh                    # the firewall and resolv.conf files the sandbox needs
RUNNER_TEMP=$(mktemp -d) scripts/run-example.sh   # the whole pipeline on the example list
node bin/run-shard.mjs --targets my.targets.json --out out/local   # clear-text results, local only
node bin/sandbox-selftest.mjs --out out/selftest  # the hostile-target self test
node scripts/check-selftest.mjs out/selftest/telemetry.jsonl
```

Requires Node 22+, Docker Engine 26+, `age`, and, for anything that runs a container, a Linux host
(x86_64 or arm64) where `install-runsc.sh` and `net-guard.sh` have run: without runsc the driver and
the self test record a skip and stop. Behind a TLS-inspecting proxy set
`SURFACE_INSTALL_CA_FILE`; with no Docker Hub access set `SURFACE_IMAGE_MIRROR` to a mirror of the
same digests; with no GitHub access `SURFACE_SOURCE_CACHE` (never set on CI).

## Operating the corpus

One-time setup by the owner:

1. Make a CI identity: `age-keygen -o ci.key`. Put the whole `AGE-SECRET-KEY-1...` line in the
   `CORPUS_TARGETS_KEY` secret of an environment named `corpus`, limited to the `main` branch. Keep
   `age-keygen -y ci.key > ci.pub` and delete `ci.key` from disk.
2. Write the target list ([targets/FORMAT.md](targets/FORMAT.md)), then
   `bin/seal-targets.sh targets.json ci.pub` and commit `targets/targets.json.age` only.
3. Set the repository variable `SURFACE_CORPUS_ENABLED` to `true`, and the loop's variables
   `LOOP_ENABLED` to `true` and `LOOP_SLOTS` to the most shard jobs a run may use at once (1 to 999;
   a run's shards are capped at it). Any other `LOOP_ENABLED` value stops the nightly run and
   hand-started self tests. Make `ci-ok` a required check.

To add or change targets, edit the clear-text list on your machine, seal it again and commit.

Pulling a run to the owner's Mac: `bin/pull-run.sh --list`, then `bin/pull-run.sh <run-id>`. It
downloads every artifact, checks it, and decrypts into
`~/company-audit/research/surface-corpus/YYYY/MM/DD/gh-<id>/decrypted/` with the archive identity at
`~/.isokron-corpus/age.key` (override with `SURFACE_ARCHIVE`, `CORPUS_KEY`). Artifacts expire after
90 days.

## Updating the engine

`node scripts/vendor-engine.mjs --from ../mcp-check --commit <sha>` copies the engine files from a
checkout of `isokron-ai/mcp-check` and records their hashes in `engine/VENDORED.json`. The rubric
version is recorded in every record and aggregate, so runs before and after can be told apart.

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
