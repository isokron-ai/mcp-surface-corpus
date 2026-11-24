# Security model

This repository runs code from many open-source MCP servers that nobody here has reviewed. Every
target is treated as hostile. This page is the whole model; `.github/workflows/corpus.yml`,
`src/docker.mjs`, `src/sandbox-run.mjs`, `gvisor.json` and `scripts/net-guard.sh` carry the details
as code, `test/` checks them, and `sandbox-selftest.yml` tries to break out of them.

## Reporting a vulnerability

Email **hello@isokron.ai** with "Security" in the subject. Do not open a public issue. A vulnerability
in the checker engine itself belongs to [isokron-ai/mcp-check](https://github.com/isokron-ai/mcp-check).

## What is public and what is not

| Data | Where | Who can read it |
|---|---|---|
| Target ids (`s001` ...) | workflow inputs, this repository | everyone |
| Target list (repos, packages, commits) | `targets/targets.json.age` | archive key holder; the CI key, inside one step |
| Raw results per target (JSON-RPC transcripts, records, logs, locks, every finding) | `surface-shard-N.tgz.age` artifact | archive key holder only (CI cannot read it back) |
| Per-target summary rows and fingerprints (no names, no tool text but tool names in fingerprints) | `surface-shard-N-rows.tgz.age`, `surface-state` | archive key + CI key (the aggregate job needs them) |
| Exact aggregate, calibration report with ids, per-target diffs | `surface-aggregate-private` | archive key holder only |
| Public aggregate and calibration report | `surface-aggregate` artifact, job summary | everyone |

The public aggregate holds counts over servers only. A count of 1 to 4 servers is withheld, and so
is a count whose complement is that small; small categories are merged into "other" until "other"
is at least 5; minima and maxima are never published; a sub-population that leaves out 1 to 4 of
its parent is shown as rates only. `src/aggregate.mjs` implements this and `test/aggregate.test.mjs`
checks it. The log and the job summaries print one `run finished, exit N` line per target, in an
order shuffled per run, where N is the harness status (0, 124 time limit, 125 harness error), never a
verdict.

## Keys

- Archive key: an age X25519 identity held by IsoKron on its own machine. `recipients.txt` holds its
  public half only. No private key is in this repository, in CI, or read by any script here.
  `bin/pull-run.sh` passes the identity file to `age` by path.
- CI key (`CORPUS_TARGETS_KEY`): a second age identity, stored only as a secret of the `corpus`
  environment (deployment branches: `main`). It is read by the decrypt step of each shard job and by
  the aggregate step, and by nothing else. It can decrypt the target list and the summary rows, never
  the raw results.
- `GITHUB_TOKEN` has no permission by default (`permissions: {}` in every workflow); each job that
  checks out asks for `contents: read`, and the corpus aggregate job also for `actions: read`. No
  job can write. The driver sends the token to `api.github.com` only, for the rate limit. No
  container receives it or any secret.

## Workflow hardening

- Triggers: `corpus.yml` runs on `schedule` and `workflow_dispatch` only. No `pull_request`,
  `pull_request_target` or `workflow_run`, so no pull request ever runs with the secret. `ci.yml`
  (pull requests) has no secret and runs only the public example. `sandbox-selftest.yml` runs on
  pull requests that touch the sandbox (and by hand) with no secret, no environment and no token use:
  it runs only our own hostile test target.
- Every corpus job is gated on the repository name, `refs/heads/main` and the variable
  `SURFACE_CORPUS_ENABLED == 'true'`.
- The loop guard, the first step of the corpus plan job and the only step of the self test's gate
  job (the same block in both, run by `test/workflows.test.mjs`), lets a run go on only while the
  variable `LOOP_ENABLED` is exactly `true` and `LOOP_SLOTS` is a whole number from 1 to 999;
  otherwise it ends with a notice and every later step and job is skipped. A pull request's self
  test goes on regardless. A corpus run never has more shards than `LOOP_SLOTS`.
- Workflow inputs pass through `env:` only and are validated by `scripts/check-batch.sh` twice (plan
  job and each shard job, which also checks the matrix itself and the slot cap).
- Every action is pinned by full commit SHA; `persist-credentials: false` on checkout.
- One run at a time (`concurrency: surface-corpus`, no cancel).
- The engine is verified against `engine/VENDORED.json` (sha256 per file) before any run.

## Sandbox

No target code runs on the runner. The host fetches bytes from fixed hosts (GitHub, the MCP Registry),
pipes them into containers on stdin, and parses JSON that containers print.

gVisor: `scripts/install-runsc.sh` (run as root before any target, before net-guard.sh because it
restarts the Docker daemon) installs the runsc release pinned in `gvisor.json` after checking the
bundle's sha512 and that it holds only the expected files, and registers it with Docker as the
runtime `runsc` with exactly the flags `src/runsc.mjs` derives from that file: gVisor's own network
stack (`--network=sandbox`), no raw sockets (`--net-raw=false`), and a syscall trace of the file,
process, network and privileged families written to `/var/log/isokron-runsc/` (mode 0750, readable
by the group of the user who ran the install, nobody else). Every container that runs target code,
and every helper of ours, the egress proxy included, runs with `--runtime runsc`; no container
may name runc. Before any target the driver
(`src/sandbox-run.mjs` preflight) checks that the daemon's runsc has exactly the pinned flags, that
net-guard.sh's resolv.conf files are in place, and that a smoke container runs under runsc as 65534
and leaves its trace. If any of that fails it writes a `skip` record with the reason and stops with a
harness error: nothing falls back to runc.

Every container that runs target code (install and server):

- digest-pinned image (`images.json`, or the target's own image, which must be pinned by digest);
- `--runtime runsc`, user `65534:65534` (nobody), `--cap-drop ALL`, `--security-opt no-new-privileges`,
  read-only root filesystem, tmpfs `/tmp`;
- `--memory 2g` (no swap beyond it), at most 2 CPUs, at most 512 processes and threads:
  `--ulimit nproc=512:512`, which gVisor's kernel enforces inside the sandbox (a fork past it fails
  with EAGAIN). `--pids-limit 2048` bounds the sandbox's own host tasks (gVisor's threads and a stub
  process and thread per sandboxed process) as a backstop; under gVisor it does not count the
  processes inside the sandbox, and at 512 a fork bomb crashed the sandbox at about 240 processes;
- named Docker volumes only: never a host path, the workspace, `RUNNER_TEMP`, `_actions` or the
  Docker socket (the one bind mount is net-guard.sh's resolv.conf, read-only). Docker's data-root
  (`docker_root`: images, containers, their logs) and its volumes folder are each a filesystem of
  their own (`install-runsc.sh`: ext4 files of `docker_fs_mb` and `volume_fs_mb` with their pinned
  inode counts, reserved up front and formatted without discard, fstrim's timer stopped, mounted
  before any volume exists; overlay2, not containerd's image store, so images stay on the
  data-root). The strict preflight checks all of it, the reservations included. So a huge image
  layer, or an install or server that writes without end, an archive bomb say, meets ENOSPC there
  instead of filling the runner's disk or running it out of inodes;
- every container we start keeps at most `container_logs` of its output (`--log-driver local`,
  `max-size`, `max-file`, checked against `docker inspect`), and that is the daemon's default too
  (`daemon.json`, checked by the strict preflight): a target that prints without end, or a flood of
  DNS queries or CONNECTs at the logger or the proxy, cannot fill a disk with logs; the logger and
  the proxy also print at most 20,000 lines each and count the rest, so rotation never drops their
  first lines unseen; a target's own image is removed once it is done, and a shard stops before a
  target when Docker's data filesystem has less than 3 GB free;
- what the harness reads back out of a work volume (lock files) is read by a helper of ours with
  the volume read-only, only once no target container of it is running (checked, not assumed), and
  only when the path resolves to itself inside `/work`: a link anywhere in it, the last part or a
  folder above, is refused, never followed;
- an environment of the names the harness sets only: runner, Actions, token and loader names are
  refused whatever the value, and so is any value the host keeps under a secret name
  (`src/sandbox-env.mjs`). The settings are read back from the exact `docker run` arguments and
  recorded with a digest in the telemetry;
- a per-step deadline and a per-target time limit (default 600 s, at most 1800 s). At a limit the
  container is removed (`docker rm -f`), which kills its whole process tree; a final sweep removes
  every container, network and volume labelled with the run.

Network:

- Both sandbox networks are `--internal`, with fixed subnets in `10.213.52.0/22`: install
  `10.213.54.0/24`, run `10.213.53.0/24`. Our network logger (`sandbox/netlog.mjs`, under runsc) sits
  at `.2` of each and is the only name server in the containers' resolv.conf: an A query for any
  name gets the logger's own address, so whatever a target looks up it connects to the logger next,
  which keeps the TLS server name or HTTP host and path and the first bytes, logs them, and closes
  without answering. Nothing reaches a real service through it.
- Install: the network's other member is our allowlist proxy (`sandbox/egress-proxy.mjs`, at `.3`).
  The proxy accepts `CONNECT` to port 443 of the kind's registry hosts only (npm:
  `registry.npmjs.org`; PyPI: `pypi.org`, `files.pythonhosted.org`; Go: `proxy.golang.org`,
  `sum.golang.org`, `storage.googleapis.com`), refuses plain HTTP, and logs each attempt with bytes
  up and down.
- Server, stdio and http alike: the run network, shared with the logger and our probe container only.
- `scripts/net-guard.sh` (run as root before any target) logs and drops, in chains of its own jumped
  to from `DOCKER-USER`: anything from or to `10.213.52.0/22` that leaves its own /24; forwarded
  traffic to `169.254.0.0/16` and `168.63.129.16` (cloud metadata and host agent) from every container
  network; all traffic from Docker bridges to the runner itself; and the same for IPv6. It refuses to
  proceed if `DOCKER-USER` is not in the forward path or an `ACCEPT` comes before it, and writes the
  resolv.conf files. The kernel log lines (prefixes `isk-sbx-*`) are read back into the telemetry.
  On the `ci` lane the corpus fails closed: a kernel log it cannot read stops the shard at the
  preflight, and a target whose containers left no syscall trace, or whose window of the kernel log
  cannot be read, is a harness error (exit 125) and its row is left out of the results.
- Docker Engine 26.0.0 or later is required (older `--internal` networks resolved outside names,
  CVE-2024-29018).

Telemetry ([docs/TELEMETRY.md](docs/TELEMETRY.md)): every run writes one JSON line per event:
settings and their digest, each container and its runtime, a summary of each container's syscall
trace (the trace file is summarised, then deleted), DNS queries and connection attempts seen by the
logger, the proxy's requests, the firewall's drops, and a `skip` when the sandbox is not there. A
corpus shard's telemetry is encrypted with the rest of its results. The self test's telemetry holds
only our own hostile target's activity and is uploaded in the clear.

Self test: `sandbox-selftest.yml` runs `selftest/hostile.py` in this sandbox once per escape attempt
(direct IP, DNS over HTTPS by IP, raw socket, IPv6, ICMP, the Docker host, cloud metadata, a token in
the environment, a write outside the work volume, a fork bomb, forged output, links planted to
outside the work folder with the result readout run over them, unix sockets of the host and abstract
ones with listeners a later stage tries while the case runs and again once it is torn down, a stdout
flood, a daemon and a nohup child that try to outlive their stage, /proc and /sys searched for the
host's facts, descriptors run out, the clock set and a measured_at claimed), and on the install
network, the most permissive one, the way an install with scripts runs (the `node24-build` image,
`HTTPS_PROXY` to the egress proxy): a CONNECT to a host not on the allowlist and plain HTTP (with a
positive control: the proxy's own log must also show a working tunnel to the registry, so a proxy
that refused everything would not pass), to IP
literals, to ports other than 443, direct egress around the proxy, cloud metadata (directly and
through the proxy), the host, and an archive bomb (a gibibyte from a megabyte, twenty thousand
entries, deep folders, entries that climb out, then an allocation past the work volume's cap, after
which the volume's image must still be fully reserved), and git submodules over ext::, file:// and
an outside host, and an npm git dependency on another. Refusing ext:: and file:// in a submodule is
git's own default; what the sandbox adds is that a target cannot change it (GIT_ names are refused
in its environment) and that the proxy refuses both outside hosts. git-lfs is not in the build
images, so LFS is not tested. A case passes only when the harness's own evidence (trace,
logger, the proxy's own log, firewall log, `docker inspect`, a listener on the host) shows it was
blocked and logged, never on what the target printed; `scripts/check-selftest.mjs`
then checks the same from the telemetry alone. Some cases have a later stage, our code run after
the case's container ended or was torn down, that looks at what it left behind: the readout over
its planted links, connections to its listeners, the size of its work volume's filesystem and how
far the runner's disk fell.

What the sandbox does not do:

- The allowlist is by host name. A package registry serves arbitrary packages, so an install can
  still fetch any package from that registry (that is how dependencies arrive). Data exfiltration
  through the registry is possible in principle; there is nothing secret inside the container to
  exfiltrate.
- PyPI installs may build source distributions, which runs the package's build code inside the
  install container. npm install scripts are off unless the list sets `install_scripts: true`.
- gVisor narrows the host kernel surface a target can reach; it does not remove it. An escape needs
  a gVisor bug and then a host kernel bug, and would reach a GitHub-hosted runner that is discarded
  after the job and holds only the read-only token and, during two steps, the CI key. The egress
  proxy runs under gVisor too: gVisor's own network stack does not reach Docker's DNS, so the host
  resolves the allowlisted registry names and the proxy gets them as fixed host entries (public
  IPv4 addresses only) and looks nothing up itself. It runs no target code but parses the
  `CONNECT` lines an install sends.
- The syscall trace covers the families listed in `gvisor.json` and is summarised, not kept whole;
  runsc limits each logged argument to `strace.log_size` bytes. Traces live on a filesystem of
  their own (`trace_fs_mb`, a loop-mounted ext4 file made by `install-runsc.sh`), so they cannot
  fill the runner's disk; a container whose trace passes `trace_max_mb` is stopped and recorded as
  `trace_overflow`, and the ci lane checks free disk before each target.
- runsc prints path arguments without quoting, so a target can put a line break in a file name and
  write lines into its own trace that look like runsc's, header included. The summary ignores lines
  without runsc's header, flags headerless lines after the first call and call lines that do not
  close (`injection_suspected`), and marks every summary `target_influenced`. The self test refuses
  a verdict from a flagged trace. A trace is evidence a target could have shaped; structured trace
  output in place of the text log is the follow-up that removes this.
- The network logger and the firewall log are rate limited and capped (net-guard.sh logs at most
  about 20 lines a second after a burst of 200; a logger container prints at most 20,000 lines),
  so a target that floods them is counted, not logged line by line.
- No tool is called, no prompt fetched, no resource read. The probe sends `initialize`, the
  `initialized` notification and the five `*/list` requests only (with pagination), and answers
  `ping` and `roots/list` with empty results.
