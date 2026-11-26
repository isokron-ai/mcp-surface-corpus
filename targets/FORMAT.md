# Target list format (`isokron-surface-targets/1`)

The real list is never committed in clear text. It lives at `targets/targets.json.age`, encrypted by
`bin/seal-targets.sh` to two public keys: the archive key in `recipients.txt` and the public half of
the CI key (`CORPUS_TARGETS_KEY`). `targets/example.targets.json` is the public example in the same
format. `src/targets.mjs` is the validator; this page describes what it accepts.

```json
{
  "format": "isokron-surface-targets/1",
  "about": "free text",
  "defaults": { "timeout_s": 600 },
  "targets": [ { "id": "s001", "repo": "owner/name", "commit": "<40-hex>", "subdir": "src/x", "launch": { ... } } ],
  "dropped": [ { "id": "s007", "why": "free text" } ]
}
```

Unknown fields anywhere are an error.

## Target

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `s` and 3 or 4 digits. Compared by number (`s009` = `s0009`). Never reused: a removed target moves to `dropped[]` with its id. Ids are the only target-specific value that is ever public (in workflow inputs). |
| `repo` | yes | `owner/name` on GitHub. |
| `commit` | one of | A full 40-character SHA. The run reads exactly that commit (recorded as `pinned: true`). |
| `ref` | one of | A branch or tag, resolved to a SHA at each run (recorded as `pinned: false`). Set exactly one of `commit` and `ref`. |
| `subdir` | no | The server's folder inside a monorepo. Relative, no `..`. |
| `registry` | no | The server's name in the official MCP Registry (`namespace/name`), for layer (a). |
| `launch` | no | How to install and start the server (layer (b)). Without it only layers (a), (c), (d) run. |
| `timeout_s` | no | Whole-target time limit, 30 to 1800 (default `defaults.timeout_s`, else 600). |
| `note`, `added` | no | Free text, kept in the encrypted record only. |

## `launch`

Common fields:

| Field | Meaning |
|---|---|
| `kind` | `npm`, `pypi`, `go` or `docker`. |
| `args` | Arguments after the server command (at most 40 strings). |
| `env` | Names the server reads. `null` makes a dummy value (shaped by the name: `*_TOKEN`, `*_URL`, ...); a string is used as given. Never put a real credential here: the run is always credential-free. Names the harness owns (`PATH`, `HOME`, `NODE_OPTIONS`, `*_PROXY`, `GITHUB_*`, `RUNNER_*`, `SURFACE_*`, ...) are refused. |
| `transport` | `stdio` (default) or `http`. |
| `http` | For `http`: `{ "port": 1024-65535, "path": "/mcp" }`. The server runs on an `--internal` network with the probe only. |

Per kind:

| Kind | Fields | Install (sandboxed, egress to the named registry only) | Run |
|---|---|---|---|
| `npm` | `package`, `version` (exact or `latest`), `bin`, `install_scripts` (default false: `--ignore-scripts`), `node` (`"22"` or `"24"`, default 24) | `npm install --omit=dev` into the target's volume via `registry.npmjs.org`; with `install_scripts`, in the full image of the same Node release (`node24-build` or `node22-build`) so native modules build from source against its headers | `node <bin script> <args>`, in the slim image |
| `pypi` | `package`, `version` (exact or `latest`), `entry` (console script, default the package name), `constraints` (up to 10 version limits on dependencies, installed alongside the package, e.g. `"mcp<2"` for a server written against the 1.x SDK), `extras` (one to four extras installed with it, `pkg[mcp]`, e.g. the one holding the MCP server) | venv + `pip install` via `pypi.org`, `files.pythonhosted.org`; `pip freeze` kept as the lock | `<venv>/bin/<entry> <args>` |
| `go` | `module` (package path of the main package), `version` (`vX.Y.Z`, a commit, or `latest`) | `go install` with `CGO_ENABLED=0` via `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com`; `go version -m` kept as the lock | the static binary, in the node24 image |
| `docker` | `image` (must be `name@sha256:<digest>`), `entrypoint` | none (the image is pulled by digest, `linux/amd64` only) | the image, with the same sandbox flags, in the image's own WORKDIR (`/tmp` when it sets none, or when it is under `/proc`, `/sys` or `/dev`: `workdir_refused`), with a size-capped tmpfs (32 MiB, at most 8) over each VOLUME it declares that is an empty folder in the image and holds neither the WORKDIR nor the entrypoint's folder (the rest: `volumes_dropped`); an image whose platform is not `linux/amd64` is not run (`platform_unsupported`) |

`latest` is allowed so a list can follow a fast-moving server; the version actually installed is
recorded, and the diff against the previous run reports the change.

## Choosing targets

- Prefer `commit` (reproducible) and an exact package version that matches it.
- A server that needs a real account to list its tools still belongs on the list: the record shows
  whether it starts with no env and with dummy env, and layers (c) and (d) still read its source.
- Check a new list with `node -e` via `bin/seal-targets.sh` (it validates before encrypting), then
  run it locally: `node bin/run-shard.mjs --targets my.targets.json --out out/local`.
