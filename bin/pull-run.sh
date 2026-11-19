#!/usr/bin/env bash
# pull-run.sh: archive ONE surface-corpus CI run by its ID, on IsoKron's own machine, and decrypt it.
# Modelled on company-audit/tools/batch-dataset/archive-run.sh (same layout, same all-or-nothing rules).
#
#   bin/pull-run.sh <run-id> [--dry-run] [--no-decrypt]
#   bin/pull-run.sh --list            # the last runs of the workflow (id, date, conclusion); downloads nothing
#
# 1. checks `gh auth status` (fails loudly if gh is not logged in);
# 2. looks the run up by ID (gh run view), refuses one that is not a completed run of the corpus
#    workflow, and reads its artifact list from the API;
# 3. downloads each artifact by name into a temporary folder beside the run folder, checks every
#    artifact arrived (each encrypted one with its .age bundle), then renames the folder to
#    $SURFACE_ARCHIVE/YYYY/MM/DD/gh-<id>/encrypted/ (all or nothing);
# 4. decrypts every *.tgz.age into decrypted.partial/<bundle name>/, checking age and tar per bundle,
#    and renames it to decrypted/ only when every bundle succeeded (a failure removes the partial
#    clear text; the encrypted copy is kept);
# 5. writes run-info.json and prints where things are. It commits and pushes nothing.
#
# After step 4:
#   decrypted/surface-shard-N/<target id>/   record.json, probe-*.json (raw JSON-RPC transcripts),
#                                            static.json, analysis.json (every check, every finding),
#                                            registry.json, lock-*, steps.log
#   decrypted/surface-shard-N/_shard/        shard.json, rows.jsonl, state.jsonl, logs
#   decrypted/surface-aggregate-private/     aggregate-exact.json, calibration-exact.md,
#                                            calibration-ids.json, diffs.jsonl, rows.jsonl, state.jsonl
#   encrypted/surface-aggregate/             aggregate.json, calibration.md (public, not encrypted)
#
# Never prints target names (only the run ID, counts and paths). The key is passed to age by path
# only and is never read by this script. Steps already done for this run are skipped, so a re-run
# after a failure continues where it stopped. Artifacts expire 90 days after the run: pull before then.
set -euo pipefail
export PATH="$PATH:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
umask 077

C="$HOME/.isokron-corpus"
# shellcheck disable=SC1091
[ -f "$C/config.env" ] && . "$C/config.env"
SURFACE_ARCHIVE="${SURFACE_ARCHIVE:-$HOME/company-audit/research/surface-corpus}"
SURFACE_REPO="${SURFACE_REPO:-isokron-ai/mcp-surface-corpus}"
SURFACE_WORKFLOW_NAME="${SURFACE_WORKFLOW_NAME:-corpus}"
CORPUS_KEY="${CORPUS_KEY:-$C/age.key}"

die() { echo "pull-run: $*" >&2; exit 1; }
say() { echo "pull-run: $*"; }

ID="" DRY=0 DECRYPT=1 LIST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --no-decrypt) DECRYPT=0 ;;
    --list) LIST=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$ID" ] || die "one run ID only"; ID="$1" ;;
  esac
  shift
done

# 1. gh must be logged in.
gh auth status >/dev/null 2>&1 || die "gh is not logged in (gh auth status failed). Run: gh auth login"

if [ "$LIST" = 1 ]; then
  gh run list -R "$SURFACE_REPO" --workflow "$SURFACE_WORKFLOW_NAME" --limit 15 --json databaseId,createdAt,status,conclusion,event \
    --jq '.[] | [(.databaseId|tostring), .createdAt, .status, (.conclusion // "none"), .event] | @tsv'
  exit 0
fi
[[ "$ID" =~ ^[0-9]+$ ]] || die "usage: pull-run.sh <run-id> [--dry-run] [--no-decrypt] | --list"

TMP="$(mktemp -d)"
PARTIALS=()
LOCK=""
cleanup() {
  local p
  for p in ${PARTIALS[@]+"${PARTIALS[@]}"}; do rm -rf "$p"; done
  rm -rf "$TMP"
  [ -z "$LOCK" ] || rmdir "$LOCK" 2>/dev/null || true
}
trap cleanup EXIT

# 2. The run, by ID, and its artifact list.
gh run view "$ID" -R "$SURFACE_REPO" --json databaseId,createdAt,headSha,conclusion,event,attempt,status,workflowName > "$TMP/run.json" 2>"$TMP/err" \
  || die "gh run view $ID failed: $(head -c 300 "$TMP/err")"
read -r STATUS WF CREATED CONCL < <(node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1]));console.log([r.status,r.workflowName,r.createdAt,r.conclusion||"none"].map(x=>String(x).replace(/\s+/g,"_")).join(" "))' "$TMP/run.json")
[ "$WF" = "$SURFACE_WORKFLOW_NAME" ] || die "run $ID belongs to workflow '$WF', not '$SURFACE_WORKFLOW_NAME'"
[ "$STATUS" = "completed" ] || die "run $ID is $STATUS, not completed"
[[ "$CREATED" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] || die "run $ID has no creation time"
gh api "repos/$SURFACE_REPO/actions/runs/$ID/artifacts?per_page=100" --paginate \
  --jq '.artifacts[] | [.name, (.expired|tostring)] | @tsv' > "$TMP/artifacts.tsv" 2>"$TMP/err" \
  || die "listing the artifacts of run $ID failed: $(head -c 300 "$TMP/err")"
ARTIFACTS=()
EXPIRED=0
while IFS=$'\t' read -r name expired; do
  [[ "$name" =~ ^surface-[a-z0-9-]+$ ]] || die "unexpected artifact name in run $ID"
  ARTIFACTS+=("$name")
  if [ "$expired" = "true" ]; then EXPIRED=$((EXPIRED + 1)); fi
done < "$TMP/artifacts.tsv"
D="$SURFACE_ARCHIVE/${CREATED:0:4}/${CREATED:5:2}/${CREATED:8:2}/gh-$ID"
REL="${D#"$SURFACE_ARCHIVE"/}"
say "run $ID ($STATUS, $CONCL) -> $REL; ${#ARTIFACTS[@]} artifact(s), $EXPIRED expired"

# Every listed artifact has a folder; every one but the public aggregate holds an .age bundle.
check_bundles() { # <encrypted dir> -> 0 when complete
  local a
  [ "${#ARTIFACTS[@]}" -gt 0 ] || return 1
  for a in "${ARTIFACTS[@]}"; do
    if [ "$a" = surface-aggregate ]; then
      [ -f "$1/$a/aggregate.json" ] || return 1
    else
      [ -n "$(find "$1/$a" -name '*.tgz.age' -type f -print -quit 2>/dev/null)" ] || return 1
    fi
  done
}

# <dir with .tgz.age files> <dest>: one folder per bundle; age and tar are checked per bundle.
decrypt_into() {
  local src="$1" dst="$2" f n st
  mkdir -p "$dst" || return 1
  while IFS= read -r f; do
    n="$(basename "$f" .tgz.age)"
    mkdir -p "$dst/$n" || return 1
    age -d -i "$CORPUS_KEY" "$f" 2>/dev/null | tar -xzf - -C "$dst/$n" 2>/dev/null
    st=("${PIPESTATUS[@]}")
    if [ "${st[0]}" != 0 ] || [ "${st[1]}" != 0 ]; then
      echo "decrypt_into: bundle $n failed (age exit ${st[0]}, tar exit ${st[1]})" >&2
      return 1
    fi
    if [ -z "$(ls -A "$dst/$n")" ]; then
      echo "decrypt_into: bundle $n decrypted to nothing" >&2
      return 1
    fi
  done < <(find "$src" -name '*.tgz.age' -type f | sort)
}

if [ "$DRY" = 1 ]; then
  if [ -d "$D/encrypted" ]; then
    if check_bundles "$D/encrypted"; then say "dry run: already archived and complete ($(find "$D/encrypted" -name '*.age' -type f | wc -l | tr -d ' ') bundle(s))"
    else say "dry run: WARNING $REL/encrypted/ does not match the artifact list; a real run would stop"; fi
  else say "dry run: would download ${#ARTIFACTS[@]} artifact(s) into $REL/encrypted/ (all or nothing)"; fi
  if [ -d "$D/decrypted" ]; then say "dry run: already decrypted"; elif [ "$DECRYPT" = 1 ]; then say "dry run: would decrypt into $REL/decrypted/"; fi
  say "dry run: nothing was changed"
  exit 0
fi

# One archive of a run at a time (the lock is removed on exit).
mkdir -p "$SURFACE_ARCHIVE"
L="$SURFACE_ARCHIVE/.pull-$ID.lock"
mkdir "$L" 2>/dev/null || die "run $ID is already being pulled (lock $L); remove it if no pull-run is running"
LOCK="$L"

# 3. Download (atomic per run).
if [ -d "$D/encrypted" ]; then
  check_bundles "$D/encrypted" || die "$REL/encrypted/ exists but does not match the run's artifact list; move it aside and re-run"
  say "already downloaded"
else
  [ "$EXPIRED" = 0 ] || die "$EXPIRED of the run's artifacts have expired; nothing downloaded"
  [ "${#ARTIFACTS[@]}" -gt 0 ] || die "run $ID has no artifacts"
  mkdir -p "$D"
  DL="$D/encrypted.download"
  rm -rf "$DL"
  PARTIALS+=("$DL")
  mkdir -p "$DL"
  for a in "${ARTIFACTS[@]}"; do
    gh run download "$ID" -R "$SURFACE_REPO" -n "$a" -D "$DL/$a" >/dev/null 2>"$TMP/err" \
      || die "gh run download $ID (one artifact) failed: $(head -c 300 "$TMP/err")"
  done
  check_bundles "$DL" || die "the download does not match the run's artifact list; nothing kept"
  mv "$DL" "$D/encrypted"
fi
N="$(find "$D/encrypted" -name '*.tgz.age' -type f | wc -l | tr -d ' ')"
if [ ! -f "$D/run-info.json" ]; then
  node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1]));const k=["attempt","conclusion","createdAt","databaseId","event","headSha"];const o={kind:"github-actions",repo:process.argv[2],workflow:"surface-corpus"};for(const x of k)o[x]=r[x];o.downloaded=new Date().toISOString();console.log(JSON.stringify(o,null,1))' "$TMP/run.json" "$SURFACE_REPO" > "$D/run-info.json.tmp"
  mv "$D/run-info.json.tmp" "$D/run-info.json"
fi

# 4. Decrypt (atomic per run).
if [ "$DECRYPT" = 1 ] && [ ! -d "$D/decrypted" ]; then
  [ -f "$CORPUS_KEY" ] || die "no key file at \$CORPUS_KEY; the encrypted copy is kept in $REL/encrypted/"
  PART="$D/decrypted.partial"
  rm -rf "$PART"
  PARTIALS+=("$PART")
  if ! decrypt_into "$D/encrypted" "$PART"; then
    rm -rf "$PART"
    die "decrypt failed; partial clear text removed (encrypted copy kept)"
  fi
  mv "$PART" "$D/decrypted"
fi

# 5. Where things are.
say "$N encrypted bundle(s) in $D/encrypted"
if [ -d "$D/decrypted" ]; then
  say "decrypted in $D/decrypted ($(find "$D/decrypted" -name record.json -type f | wc -l | tr -d ' ') target record(s))"
  say "decrypted/ is clear text: keep it out of git and out of any synced folder"
fi
if [ -f "$D/encrypted/surface-aggregate/calibration.md" ]; then say "public report: $D/encrypted/surface-aggregate/calibration.md"; fi
