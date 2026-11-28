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
logs and drops anything that tries to leave, IPv6 included. An npm target with `install_scripts`
installs in the full Debian image of the same Node release (`node24-build`, `node22-build` in
`images.json`: compilers, make, python3, the Node headers), so a native module compiles from source
against those headers (`npm_config_nodedir=/usr/local`, `npm_config_build_from_source=true`; prebuilt
binaries are not fetched, their hosts are not on the allowlist), in a container hardened exactly like
any install: a compiler there runs untrusted build scripts like any install script. The server then
runs in the slim image, where the module loads with the same ABI and glibc. Before any target the driver checks that
the daemon's runsc has exactly the pinned flags and runs a smoke container under it; if anything is
missing it records a `skip` and stops: nothing falls back to runc. Each run writes telemetry
(settings, containers, syscall trace summaries, DNS queries, connections, egress, firewall drops;
[docs/TELEMETRY.md](docs/TELEMETRY.md)). `sandbox-selftest.yml` runs a hostile target through twenty-six
escape attempts and passes only when every one was blocked and logged: eighteen on the run network
(among them links planted to outside the work folder, host, abstract and left-behind sockets, a
stdout flood, daemons that try to outlive their stage, /proc and /sys probed for the host's facts,
descriptors run out, and the clock and a claimed measured_at tampered with),
and seven on the install network, run the way an npm install with scripts runs (the `node24-build`
image, `HTTPS_PROXY` set), which ask the egress proxy for other hosts, IP literals, other ports and
plain HTTP, go around it to outside addresses, metadata and the host, unpack an archive bomb, and
clone a superproject whose submodules point at ext::, file:// and an outside host.
Docker's data-root (images, containers, their logs) and its volumes each live on a filesystem of
their own, reserved up front (`docker_fs_mb`, `volume_fs_mb` and their inode counts in
`gvisor.json`), and every container keeps at most `container_logs` of its output (the `local` log
driver, per container and as the daemon's default). So a target that writes, prints or unpacks
without end, or a huge image layer, fills those, not the runner's disk.
[SECURITY.md](SECURITY.md) has the details.

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
  reference servers from `modelcontextprotocol/servers`, and IsoKron's `kronicle-lite`, whose
  `better-sqlite3` is a native module built from source in the sandbox). No secret. `ci-ok` is the one required
  status check.
- `corpus.yml` (nightly 07:17 UTC and `workflow_dispatch` with optional `only` ids and `shards`):
  plan, a matrix of up to 16 shard jobs (8 for the whole list, never more than `LOOP_SLOTS`), one
  aggregate job. One run at a time.
- `sandbox-selftest.yml` (`workflow_dispatch`, and pull requests that touch the sandbox or anything
  the self test imports): the loop guard, then `sandbox-conformance.yml` of the same commit with
  the mutation matrix. No secret.
- `sandbox-conformance.yml` (`workflow_call`): the shared sandbox conformance check, below.
- `conformance-nightly.yml` (every night at 03:41 UTC, and `workflow_dispatch`): the same check
  with the mutation matrix, then the public status file, below. No loop guard.
- `pin-drift.yml` (Mondays 06:17 UTC, and `workflow_dispatch`): proposes newer pins, below.

All of them run on GitHub's free hosted runners in a public repository. `corpus.yml`, and
`sandbox-selftest.yml` when run by hand, start with the loop guard: they do nothing (a notice, not a
failure) unless the repository variable `LOOP_ENABLED` is exactly `true` and `LOOP_SLOTS` is a whole
number from 1 to 999. A pull request's self test does not depend on them. `conformance-nightly.yml`
and `pin-drift.yml` are guards, not loop work, and run whatever those variables say.

### Sandbox conformance (shared)

Every repository that runs third-party servers calls the reusable workflow at a pinned commit:

```yaml
jobs:
  sandbox:
    permissions:
      contents: read
    uses: isokron-ai/mcp-surface-corpus/.github/workflows/sandbox-conformance.yml@<full sha>
    with:
      mutations: false
```

It tests the very commit it is pinned at (it checks out `job.workflow_repository` at
`job.workflow_sha`): on a fresh runner it installs gVisor and `net-guard.sh`, runs
`bin/sandbox-selftest.mjs`, and passes only when `scripts/check-selftest.mjs` recomputes a pass from
the telemetry alone. The call fails when the self test (or, with `mutations`, any mutation) fails.

| Input | Type, default | Meaning |
|---|---|---|
| `mutations` | boolean, `false` | Also run the mutation matrix: each protection off in turn, and the self test must fail for the reason that protection explains (`scripts/check-mutation.mjs`). Twenty more jobs. |
| `artifact-prefix` | string, `sandbox-conformance` | Prefix of the artifact names: lowercase letters, digits and dashes, at most 40. |

| Output | Value |
|---|---|
| `verdict` | `pass` when the self test passed and, with `mutations`, every mutation was shown; otherwise `fail`. |
| `selftest` | `pass` or `fail`, as `check-selftest.mjs` recomputed it. |
| `mutations` | `pass`, `fail`, or `skipped` when `mutations` was false. |
| `telemetry-artifact` | The artifact `<prefix>-selftest`: `telemetry.jsonl`, `results.json`, `environment.json` (never what the hostile target printed). Each mutation's is `<prefix>-mutation-<protection>`. |
| `sandbox-sha` | The commit of this repository that was tested. |
| `checked-at` | When the telemetry check ran (UTC, `YYYY-MM-DDTHH:MM:SSZ`). |
| `runner-image` | The runner image (`ImageOS/ImageVersion`, for example `ubuntu24/20261117.1`). |
| `kernel` | `uname -r` of the runner. |
| `docker` | The Docker server version. |
| `gvisor-release` | The gVisor release `gvisor.json` pins. |
| `runsc-version` | What the installed `runsc --version` reported. |

The reusable workflow's jobs run on runners of their own, so its pass says the pinned sandbox works
on today's runner image, kernel and Docker; it cannot vouch for the runner that will run targets. A
job that runs targets therefore also runs the same steps itself, on its own runner, after its
checkout and node setup and before any target, with the composite action `sandbox-guard`:

```yaml
- uses: actions/setup-node@<sha> # node 22 or later
  with:
    node-version: 22
- id: sandbox
  uses: isokron-ai/mcp-surface-corpus/sandbox-guard@<full sha>   # the same sandbox commit
  with:
    out: ${{ runner.temp }}/sandbox-selftest
```

It fails the job unless the verdict is `pass`, and has the outputs `sandbox-sha` (the commit it ran
from), `verdict`, `out`, `checked-at`, `runner-image`, `kernel`, `docker`, `gvisor-release` and
`runsc-version` (as above). Never upload `<out>/untrusted/`.

Use it at a full commit SHA: `@main`, a tag or any other branch fails its first step, because the
sandbox under it could then change without review on the caller's side. Its input
`allow-local-checkout: 'true'` is only for this repository's own `sandbox-conformance.yml`, which
checks out a validated commit itself and runs the action from that checkout.

### Nightly status

`conformance-nightly.yml` publishes the night's result as the asset `conformance-status.json` of the
release tagged `conformance` in this repository, readable without a token:

```
https://github.com/isokron-ai/mcp-surface-corpus/releases/download/conformance/conformance-status.json
```

A release asset, not an Actions artifact: artifacts need a token to download even from a public
repository, and expire.

The publish job decides pass or fail itself. It never runs a target and never reads the outputs of
the jobs that did: a target that got out of its sandbox could write a job output in one line. It
downloads the telemetry the self test and each mutation uploaded and recomputes both verdicts with
its own checkout's checkers (`scripts/verify-conformance.mjs`: `check-selftest.mjs`, and
`check-mutation.mjs` for every protection). The run, attempt and commit come from its own
environment. `sandbox-selftest.yml` runs the same recomputation on every pull request (its
`evidence` job). This catches wiring bugs between jobs and keeps the verdict in a job that never ran
a target. It is not a defence against a compromised self test runner: the telemetry is written on
that runner, so a target that took it over could write evidence that recomputes as a pass. A
separate job that signs provenance for the evidence would be the fix if that is ever needed.

`scripts/publish-conformance.sh` then refuses (uploads nothing) when the status does not supersede
the published one: a later run (higher `run_id`), or a later attempt of the same run, with evidence
no older. A re-run of an old night therefore never puts its green back over a newer red. A green
status for another commit than main's head at that moment (main moved during the run, or a re-run
tested an old commit) is published as not ok, with `result` `main_moved`: it says nothing about
main, and publishing nothing would leave an older green up. A red status is always published when
it supersedes.

The file holds no secret and nothing a target printed:

| Field | Value |
|---|---|
| `format` | `isokron-sandbox-conformance/1` |
| `ok` | `true` only when the call succeeded, `selftest` is `pass` and `mutations` is `pass`. |
| `selftest`, `mutations` | As the outputs above (`fail` when missing). |
| `result` | The conformance call's result: `success`, `failure`, ...; or `main_moved` (then `ok` is false) when a green was for another commit than main's head at publish. |
| `checked_at` | When the self test's evidence ended (UTC, never later than the publish); the publish time if there is none. |
| `run_id`, `run_attempt`, `run_url` | The nightly run. |
| `sandbox_sha` | The commit tested: main's head when published. |
| `runner_image`, `kernel`, `docker`, `gvisor_release`, `runsc_version` | What the self test's runner reported about itself (labels, not part of the verdict); `unknown` when not known. |

A red result is published too, so readers react at once. A cancelled run publishes nothing, and the
last status ages. tool-qa's pump and watchdog read this file as a circuit breaker: while it is not
`ok`, is more than 36 hours old, or cannot be read, no lane that runs third-party code is
dispatched. If it goes stale, check that GitHub has not disabled `conformance-nightly.yml` for
inactivity (scheduled workflows stop after 60 days without a commit), and run it by hand.

### Pin drift

`pin-drift.yml` runs `scripts/pin-drift.mjs --open-pr` weekly. It compares the pinned gVisor
release (`gvisor.json`), age (`scripts/install-age.sh`) and actions (`pins/actions.json`) with their
newest releases. The age tarball is downloaded, hashed and verified against the release attestation
age's own release workflow signed (`gh attestation verify --repo FiloSottile/age`); without a valid
one nothing is proposed. The gVisor and action pins are trust on first use, and the pull request
says so: a new gVisor bundle is downloaded and its sha512 must match the `.sha512` file beside it,
but both come from the same bucket; an action pin is the commit its release tag points to today. It then opens a pull request through the API, with the job token's
`contents: write` and `pull-requests: write` and nothing else.

That token cannot do two things, by GitHub's design, so the pull request says what a person does
before merging:

- It cannot change workflow files. Action pins therefore land in `pins/actions.json` (the one
  record of them: `test/workflows.test.mjs` fails while a `uses:` line differs from it). Check out
  the branch, run `node scripts/pin-drift.mjs --sync-workflows`, and commit and push the result.
- A pull request it opens starts no workflow. The push above starts `ci` and `sandbox-selftest` on
  the pull request; with nothing to sync, close and reopen the pull request instead. Merge only when
  both pass; the next nightly run then checks the new pins on main.

`node scripts/pin-drift.mjs --check` prints what is behind without opening anything (exit 3 when
something is).

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

The vendored copy is mcp-check 22c76a6 (19 Nov 2026, rubric 2.1.0), older than mcp-check's current reader. It is used
only for this repository's own layer analysis. A caller that compares a static list with a live one should hand the
static step its own reader instead: `bin/run-shard.mjs` takes a `reader` option (`{ dir, id, entry }`), puts that
folder in the tools volume as `reader/`, and `sandbox/static.mjs --reader` returns that reader's answer as `reader` in
`static.json`. mcp-check's live-probe lane does this with its own `corpus/static-read.cjs`.

Some servers write into their own install at start (a logs folder in site-packages) or to `/data`, and fail on the
read-only work volume. A caller that wants them started passes `writableWork: true` (or `--writable-work`): each
probe of a package kind then gets a writable layer of its own, an overlay over the work volume at `/work` and a
32 MiB `/data` tmpfs, removed after the probe; the work volume itself is never written (SECURITY.md, and the
`work-overlay` case of the self test). Records say so in `writable_work`.

## Licence

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Checking that a test fails when its guard is removed (mutation probes)

Do not clone the repository to check this by hand: run the `mutation-probe` workflow (Actions, or
`gh workflow run mutation-probe.yml -R isokron-ai/mcp-surface-corpus -f ref=<branch-or-sha> -f test='node --test test/<file>.test.mjs' -f mutations='[...]'`).
It calls isokron-ai/tool-qa's reusable workflow. Each mutation is `{"id", "file", "find", "replace"}`
(and optionally its own `test` and `pattern`): `find` must be exact text that occurs exactly once in `file`, for example
a protection in `src/`, `sandbox/` or `bin/`. Every mutation runs in a fresh checkout of `ref`: the test must pass first, then it
runs again with the edit applied. The job summary lists each mutation as `killed` (the test failed, as it must),
`survived` or `stale` (`find` is not there exactly once), and the `mutation-probe-results` artifact holds the same as
JSON. The run fails if any mutation survived or is stale. At most 20 mutations per run; read-only, no secrets.
