# Security model

This repository runs code from many open-source MCP servers that nobody here has reviewed. Every
target is treated as hostile. This page is the whole model; `.github/workflows/corpus.yml` and
`src/docker.mjs` carry the details as code, and `test/` checks them.

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
- `GITHUB_TOKEN` is read-only (`contents: read`; `actions: read` in the aggregate job). The driver
  sends it to `api.github.com` only, for the rate limit. No container receives it or any secret.

## Workflow hardening

- Triggers: `schedule` and `workflow_dispatch` only. No `pull_request`, `pull_request_target` or
  `workflow_run`, so no pull request ever runs with the secret. `ci.yml` (pull requests) has no secret
  and runs only the public example.
- Every job is gated on the repository name, `refs/heads/main` and the variable
  `SURFACE_CORPUS_ENABLED == 'true'`.
- Workflow inputs pass through `env:` only and are validated by `scripts/check-batch.sh` twice (plan
  job and each shard job, which also checks the matrix itself).
- Every action is pinned by full commit SHA; `persist-credentials: false` on checkout.
- One run at a time (`concurrency: surface-corpus`, no cancel).
- The engine is verified against `engine/VENDORED.json` (sha256 per file) before any run.

## Sandbox

No target code runs on the runner. The host fetches bytes from fixed hosts (GitHub, the MCP Registry),
pipes them into containers on stdin, and parses JSON that containers print.

Every container that runs target code (install and server):

- digest-pinned image (`images.json`, or the target's own image, which must be pinned by digest);
- user `10001:10001`, `--cap-drop ALL`, `--security-opt no-new-privileges`, read-only root filesystem,
  tmpfs `/tmp`;
- `--memory 2g` (no swap beyond it), `--pids-limit 512`, at most 2 CPUs;
- named Docker volumes only: never a host path, the workspace, `RUNNER_TEMP`, `_actions` or the
  Docker socket;
- a per-step deadline and a per-target time limit (default 600 s, at most 1800 s). At a limit the
  container is removed (`docker rm -f`), which kills its whole process tree; a final sweep removes
  every container, network and volume labelled with the run.

Network:

- Install: the container is on an `--internal` network whose only other member is our allowlist
  proxy (`sandbox/egress-proxy.mjs`). The proxy accepts `CONNECT` to port 443 of the kind's registry
  hosts only (npm: `registry.npmjs.org`; PyPI: `pypi.org`, `files.pythonhosted.org`; Go:
  `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com`), refuses plain HTTP, and logs each
  attempt with bytes up and down.
- Server, stdio: `--network none`.
- Server, http: an `--internal` network shared with the probe container only.
- `scripts/net-guard.sh` (run as root before any target) drops forwarded traffic to
  `169.254.0.0/16` and `168.63.129.16` (cloud metadata and host agent) and all traffic from Docker
  bridges to the runner itself, and refuses to proceed if Docker's `DOCKER-USER` chain is not in the
  forward path.
- Docker Engine 26.0.0 or later is required (older `--internal` networks resolved outside names,
  CVE-2024-29018).

What the sandbox does not do:

- The allowlist is by host name. A package registry serves arbitrary packages, so an install can
  still fetch any package from that registry (that is how dependencies arrive). Data exfiltration
  through the registry is possible in principle; there is nothing secret inside the container to
  exfiltrate.
- PyPI installs may build source distributions, which runs the package's build code inside the
  install container. npm install scripts are off unless the list sets `install_scripts: true`.
- No gVisor or seccomp profile beyond Docker's default. A kernel escape from an unprivileged
  container would reach a GitHub-hosted runner that is discarded after the job and holds only the
  read-only token and, during two steps, the CI key.
- No tool is called, no prompt fetched, no resource read. The probe sends `initialize`, the
  `initialized` notification and the five `*/list` requests only (with pagination), and answers
  `ping` and `roots/list` with empty results.
