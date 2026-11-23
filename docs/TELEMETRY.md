# Run telemetry

Every sandbox run writes one telemetry file: [JSON Lines](https://jsonlines.org/), one record per
line, UTF-8, appended in order. The harness writes it and nothing else does. A target's own output
is never a record; at most its size and hash are (`target_output`).

- Corpus shard: `out/_shard/telemetry.jsonl`, written by `bin/run-shard.mjs`. It names target ids
  and the host names targets looked up, so it travels inside the encrypted shard bundle
  (`surface-shard-N.tgz.age`, archive key only), like every other per-target result.
- Sandbox self test: `telemetry.jsonl` in the `--out` folder of `bin/sandbox-selftest.mjs`. Its
  targets are our own hostile controls (`selftest/hostile.py`), so the workflow
  `sandbox-selftest.yml` uploads it as a plain artifact.

`src/telemetry.mjs` is this schema as code. `validateRecord()` checks every record before it is
written, and a record that fails is never written. `readTelemetry()` reads a file back and reports
every line that is not a valid record instead of dropping it. `scripts/check-selftest.mjs` checks a
self test run from this file alone. `test/telemetry.test.mjs` checks that this page names every
record type, field, source, role and skip reason in the code.

Schema version: `v` = 1. A change that removes or renames a field, or changes its meaning, raises
the version.

## Envelope

Every record has these fields:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Schema version, `1`. |
| `type` | string | One of the record types below. |
| `run` | string | The run id, `[0-9a-z-]{4,40}`. The self test uses the UTC start time and a random suffix (`20261121t100000-3f9a1c`); a corpus shard uses its run id (12 hex digits). Every record of a file has the same `run`. |
| `seq` | integer | 0, 1, 2, ... in the order written. A gap or a repeat means the file was changed. |
| `t` | string | When the record was written, ISO 8601 UTC with milliseconds. |
| `source` | string | Who saw it (see [Sources](#sources)). |
| `subject` | string or null | What it is about: a corpus target id (`s001`), a self test case (`case:direct-ip`), or null for the run as a whole (preflight, smoke container, baseline). `[a-z0-9:_-]{1,48}`. |
| `role` | string or null | The part the container or address had (see [Roles](#roles)), or null. |

A record is at most 256 KiB as JSON. Numbers that came from a container are clamped to the schema
(a port outside 0 to 65535 is null), and a record built from a container's data that the schema
still refuses is left out and counted in `run_end` (`telemetry_dropped`), so it cannot stop the run. Strings that came from a target (names it looked up, paths
it opened, bytes it sent) are cut to a fixed length and kept as printable text, with every other
byte written as `\xHH`. Treat them as untrusted data.

## Sources

| Source | What it is |
|---|---|
| `harness` | The harness itself (`bin/run-shard.mjs`, `bin/sandbox-selftest.mjs`, `src/sandbox-run.mjs`): run start and end, the runtime check, settings, containers, skips, verdicts. |
| `netlog` | The network logger and DNS sinkhole (`sandbox/netlog.mjs`) at .2 of each sandbox network: every DNS query and every connection that reached it. |
| `proxy` | The egress proxy (`sandbox/egress-proxy.mjs`) on the install network: every request, allowed or refused. |
| `runsc` | gVisor's syscall trace of one container, summarised (`src/trace-summary.mjs`). |
| `host` | The runner's firewall (`scripts/net-guard.sh`): packets it logged and dropped, read back from the kernel log (`src/sandbox-net.mjs`). |

## Roles

| Role | Meaning |
|---|---|
| `install` | A container that installs a target's package. |
| `server` | A container that runs a target's server. |
| `probe` | Our HTTP probe, beside an HTTP server on the run network. |
| `netlog` | The network logger. |
| `proxy` | The egress proxy. |
| `helper` | Another container of ours (static reader, analyser, file copy). |
| `baseline` | Our empty server, run once per shard to measure what starting a container costs. |
| `smoke` | The preflight container that proves runsc runs as user 65534 and writes a trace. |
| `case` | A self test case container (`selftest/hostile.py`). |

## Record types

Fields in the tables are required unless marked optional.

### `run_start`

The first record of a file.

| Field | Type | Meaning |
|---|---|---|
| `kind` | `corpus` or `selftest` | Which program wrote the file. |
| `lane` | string | `ci` or `local`. |
| `node` | string | Node.js version of the harness. |
| `platform` | string | Host OS and CPU, as `linux/x64`. |
| `runtime` | string | The container runtime every target container must use: `runsc`. |
| `gvisor_release` | string | The pinned gVisor release from `gvisor.json`. |

### `runtime`

What the preflight found. Written once per run.

| Field | Type | Meaning |
|---|---|---|
| `available` | boolean | The Docker daemon has a runtime named `runsc`. |
| `name` | string | `runsc`. |
| `release` | string | The pinned release. |
| `flags_expected` | array of strings | The runsc flags `gvisor.json` gives (`src/runsc.mjs runscFlags`). |
| `flags_daemon` | array of strings | The flags the daemon actually has for runsc. |
| `flags_match` | boolean | Both lists hold the same flags. |
| `smoke` | `ok`, `failed` or `not_run` | Whether the smoke container ran under runsc as 65534 and left a trace. |

### `skip`

Something the run needed was not there, and the run (or one part of it) stopped instead of
running without it. There is never a fallback to runc.

| Field | Type | Meaning |
|---|---|---|
| `reason` | string | One of the [skip reasons](#skip-reasons). |
| `detail` | string | One line of explanation, at most 300 characters. |

#### Skip reasons

| Reason | When |
|---|---|
| `runtime_unavailable` | No Docker daemon, no `runsc` runtime, or a container could not start under runsc as 65534. |
| `sandbox_setup_missing` | runsc is registered with flags other than `gvisor.json` gives, `scripts/net-guard.sh` has not written its resolv.conf files, or the harness stopped before its sandbox check. |
| `network_setup_failed` | A sandbox network could not be made as declared. Defined in the schema; this version reports that case as a harness error instead. |
| `trace_unavailable` | runsc wrote no syscall trace for a container. In the preflight this stops the run; for one container it is recorded and that container's evidence is incomplete. |
| `host_log_unavailable` | The kernel log (the firewall's drops) cannot be read. The self test stops; the corpus records it and goes on. |
| `disabled` | The run was switched off. Defined in the schema; in this version the workflows stop before the harness starts, so it is not written. |

### `settings`

The settings of one container, read back from the exact `docker run` arguments the harness used
(`src/sandbox-env.mjs settingsManifest`), so what is recorded is what ran.

| Field | Type | Meaning |
|---|---|---|
| `digest` | hex string | SHA-256 of the manifest as canonical JSON (keys sorted). |
| `manifest` | object | `format`, `role`, `runtime`, `user`, `cap_drop`, `cap_add`, `security_opt`, `read_only`, `init`, `tmpfs`, `pids_limit`, `memory`, `memory_swap`, `cpus`, `ulimits`, `network`, `ip`, `aliases`, `hosts`, `workdir`, `mounts`, `env_names` (names only), `env_sha256`, `entrypoint`, `image`, `cmd_sha256`, `cmd_argc`. No env value and no command text. |

### `container`

How one container ended.

| Field | Type | Meaning |
|---|---|---|
| `runtime` | string | The runtime `docker inspect` reports. Anything but `runsc` for target code is a failure. |
| `exit` | integer or null | Exit status, or null when unknown. |
| `signal` | string or null | The signal that ended the client process, if any. |
| `timed_out` | boolean | The harness stopped it at its time limit. |
| `oom_killed` | boolean or null | The memory limit killed it; null when it could not be inspected. |
| `ms` | integer | Wall time from start to end. |

### `dns_query`

One DNS query the network logger answered (source `netlog`). The logger is the only name server
a sandbox container has.

| Field | Type | Meaning |
|---|---|---|
| `from` | IP or null | The address that asked (map it to a role with the network's fixed addresses). |
| `proto` | `udp` or `tcp` | |
| `qname` | string | The name, lower case, at most 253 characters. |
| `qtype` | string | `A`, `AAAA`, `HTTPS`, ... or the number. |
| `answer` | string | `sinkhole` (an A query: the logger's own address), `empty` (no records), `nxdomain` (PTR), `refused` (not a standard query), `formerr` (unreadable). |

### `connection`

One connection or datagram that reached the sinkhole (source `netlog`). The sinkhole reads what
the client sends first, keeps a little of it, and closes without answering.

| Field | Type | Meaning |
|---|---|---|
| `from` | IP or null | The sender. |
| `proto` | `tcp` or `udp` | |
| `port` | integer or null | The port it reached. |
| `bytes` | integer | Bytes received. |
| `sni` | string, optional | The TLS server name in a ClientHello. |
| `http` | object, optional | `method`, `host`, `path` (query string removed) of a plain HTTP request. |
| `first_hex` | string, optional | The first bytes, in hex (at most 32 bytes). |

### `egress`

One request to the egress proxy on the install network (source `proxy`).

| Field | Type | Meaning |
|---|---|---|
| `host` | string | The host asked for. |
| `port` | integer or null | The port asked for. |
| `allowed` | boolean | Whether it is on the install's registry allowlist (port 443 only). |
| `up` | integer, optional | Bytes sent to the registry. |
| `down` | integer, optional | Bytes received from it. |
| `ms` | integer, optional | How long the tunnel was open. |
| `error` | string, optional | Why it was refused or failed. |
| `method` | string, optional | The HTTP method of a plain HTTP request (always refused). |

### `host_drop`

Packets the runner's firewall logged and dropped, grouped by what was tried (source `host`).

| Field | Type | Meaning |
|---|---|---|
| `chain` | string | `forward` (leaving a sandbox network), `input` (to the runner itself), `forward6`, `input6` (IPv6). |
| `family` | `4` or `6` | |
| `proto` | string | `TCP`, `UDP`, `ICMP`, `ICMPv6`, ... |
| `src` | IP or null | Source address. |
| `dst` | IP or null | Destination address. |
| `dpt` | integer or null | Destination port. |
| `n` | integer | How many logged packets the group holds. The firewall's logging is rate limited, so this is a lower bound. |
| `icmp_type` | integer, optional | The ICMP type. |

### `trace_summary`

The summary of runsc's syscall trace of one container (source `runsc`). The raw trace is deleted
after it is summarised.

| Field | Type | Meaning |
|---|---|---|
| `summary` | object | `format` (`isokron-trace-summary/1`), `lines`, `syscalls`, `counts` (by family: `file`, `process`, `network`, `privileged`), `failed`, `opens_outside` (opens and writes outside the expected paths in `gvisor.json`), `credential_paths` (reads of token, key and host paths), `exec`, `process` (`clones`, `clone_failed`), `network` (`sockets`, `raw_sockets`, `connects`, `sends`, `binds`, `dns_names`), `privileged`, `omitted` (how many entries each capped list left out), `bytes`, `truncated`. Each list entry has `n`, `failed` and the last `errno`. |

### `target_output`

What a target printed, by size and hash only. The bytes are kept apart as untrusted and are never
parsed as results.

| Field | Type | Meaning |
|---|---|---|
| `stream` | `stdout`, `stderr` or `file` | |
| `bytes` | integer | Size. |
| `sha256` | hex string | Hash of what was kept. |
| `untrusted` | `true` | Always true. |
| `truncated` | boolean, optional | More was printed than was kept. |

### `case_evidence`

The evidence of one self test case that no other record holds, written just before its verdict, so
`scripts/check-selftest.mjs` can recompute the verdict from the telemetry alone (with the trace,
network logger, firewall, container and output records of the same `subject`).

| Field | Type | Meaning |
|---|---|---|
| `case` | string | The case. |
| `canary_hits` | integer or null | Connections that reached the harness's listener on the host; null when it could not listen. |
| `inspect` | object | From `docker inspect`: `runtime`, `mismatches` (against the settings manifest), `canary_in_env` (a host token value in the container's environment). |
| `telemetry_has_nonce` | boolean or null | Whether the case's nonce, or another run's record, reached the telemetry. |
| `pids_limit` | integer | The process limit the case was held to (`--ulimit nproc`). |

### `bypass_result`

The verdict of one self test case (`src/selftest.mjs`). The harness's own evidence decides it.
The target's report can make a case fail, never pass.

| Field | Type | Meaning |
|---|---|---|
| `case` | string | The case: `direct-ip`, `doh-ip`, `raw-socket`, `ipv6`, `icmp`, `docker-host`, `metadata`, `env-token`, `write-outside`, `fork-bomb`, `output-forgery`. |
| `blocked` | boolean | The attempt did not get through, and the container ran under runsc with the declared settings. |
| `logged` | boolean | The attempt shows in the harness's evidence (trace, network logger, firewall log). |
| `pass` | boolean | `blocked` and `logged`. |
| `evidence` | array of strings | At most 20 short lines saying what was seen. |
| `detail` | string | One line. |

### `run_end`

The last record of a file.

| Field | Type | Meaning |
|---|---|---|
| `records` | integer | Records in the file, this one included. |
| `skipped` | integer | How many `skip` records were written. |
| `ok` | boolean | The run finished without a harness error (corpus) or with every case passed (self test). |
| `telemetry_dropped` | integer, optional | Records built from a container's data (network logger, proxy, trace, firewall lines) that the schema refused and that were left out. A self test fails when it is not 0. |

## Example

```json
{"v":1,"type":"dns_query","run":"20261121t100000-3f9a1c","seq":41,"t":"2026-11-21T10:00:12.345Z","source":"netlog","subject":"case:metadata","role":"case","from":"10.213.53.3","proto":"udp","qname":"metadata.google.internal","qtype":"A","answer":"sinkhole"}
{"v":1,"type":"host_drop","run":"20261121t100000-3f9a1c","seq":42,"t":"2026-11-21T10:00:14.001Z","source":"host","subject":"case:icmp","role":"case","chain":"input","family":4,"proto":"ICMP","src":"10.213.53.3","dst":"10.213.53.1","dpt":null,"n":3,"icmp_type":8}
```
