#!/usr/bin/env bash
# Runs one shard. bin/run-shard.mjs prints only its label and "run finished, exit N" lines, and only
# the latter pass the filter below into the log; everything else goes to files under
# $RUNNER_TEMP/corpus/out, which the next step encrypts. The driver's exit status goes to the step
# output rc; the step itself always succeeds so the results are still encrypted and uploaded.
# Every target runs in containers (see bin/run-shard.mjs); nothing of a target runs in this shell.
# GH_TOKEN (the job's read-only token, for the GitHub API rate limit) is read by the driver's own
# fetch of repository facts and never reaches a container.
set -uo pipefail
c="$RUNNER_TEMP/corpus"
mkdir -p "$c/out/_shard"
node bin/run-shard.mjs --targets "$c/targets.json" --consume-targets --out "$c/out" --lane ci \
  --shard "${SHARD:?}" --shards "${SURFACE_SHARDS:?}" ${SURFACE_ONLY:+--only "$SURFACE_ONLY"} \
  2>>"$c/out/_shard/driver-stderr.log" \
  | grep --line-buffered -E '^run finished, exit [0-9]+$' | tee "$c/public.txt"
rc=${PIPESTATUS[0]}
rm -f "$c/targets.json"
# Last sweep, in case the driver itself died: every container, network and volume of this run.
{
  ids=$(docker ps -aq --filter label=isokron.surface.run)
  [ -z "$ids" ] || docker rm -f -v $ids
  ids=$(docker network ls -q --filter label=isokron.surface.run)
  [ -z "$ids" ] || docker network rm $ids
  ids=$(docker volume ls -q --filter label=isokron.surface.run)
  [ -z "$ids" ] || docker volume rm -f $ids
} >>"$c/out/_shard/driver-stderr.log" 2>&1 || true
[[ "$rc" =~ ^[0-9]{1,3}$ ]] || rc=125
echo "rc=$rc" >> "$GITHUB_OUTPUT"
exit 0
