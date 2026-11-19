#!/usr/bin/env bash
# Checks the corpus workflow's inputs and derives the shard count from them. Reads nothing but
# ONLY_IN and SHARDS_IN (and, in the shard jobs, PLAN_SHARDS, SHARD, JOB_INDEX, JOB_TOTAL): never a secret.
#
#   scripts/check-batch.sh output "$GITHUB_OUTPUT"   # plan job: shards=K, matrix=[1,...,K]
#   scripts/check-batch.sh env "$GITHUB_ENV"         # shard job: SURFACE_ONLY=..., SURFACE_SHARDS=K
#
# ONLY_IN: empty (every target; a scheduled run has no inputs) or comma-separated target ids such as
# s001,s014, each once (compared by number), at most MAX_IDS. SHARDS_IN: empty or 1 to MAX_SHARDS.
# K = SHARDS_IN, or DEFAULT_SHARDS for the whole list, or min(MAX_SHARDS, number of ids).
# The whole value must match (a bash regex, not grep: grep -x matches line by line, so a value with
# a newline could add lines to GITHUB_ENV). Every check runs before anything is written. In env
# mode the plan's K must equal the K derived here and the matrix itself must agree: JOB_TOTAL
# (strategy.job-total) == K and JOB_INDEX (strategy.job-index) + 1 == SHARD.
set -euo pipefail

MAX_IDS=200
MAX_SHARDS=16
DEFAULT_SHARDS=8

mode=${1:-}
file=${2:-}
if { [ "$mode" != env ] && [ "$mode" != output ]; } || [ -z "$file" ]; then
  echo "::error::usage: scripts/check-batch.sh env|output FILE"
  exit 2
fi

only=${ONLY_IN-}
re="^s[0-9]{3,4}(,s[0-9]{3,4}){0,$((MAX_IDS - 1))}\$"
if [ -n "$only" ] && ! [[ "$only" =~ $re ]]; then
  echo "::error::only must be comma-separated target ids such as s001,s014 (at most $MAX_IDS)"
  exit 1
fi

n=0
if [ -n "$only" ]; then
  IFS=, read -r -a ids <<<"$only"
  n=${#ids[@]}
  declare -A seen=()
  for id in "${ids[@]}"; do
    num=$((10#${id#s}))
    if [ -n "${seen[$num]+x}" ]; then
      echo "::error::only names a target id twice"
      exit 1
    fi
    seen[$num]=1
  done
fi

want=${SHARDS_IN-}
if [ -n "$want" ]; then
  if ! [[ "$want" =~ ^[0-9]{1,2}$ ]] || [ "$((10#$want))" -lt 1 ] || [ "$((10#$want))" -gt "$MAX_SHARDS" ]; then
    echo "::error::shards must be a whole number from 1 to $MAX_SHARDS"
    exit 1
  fi
  shards=$((10#$want))
elif [ "$n" -eq 0 ]; then
  shards=$DEFAULT_SHARDS
elif [ "$n" -gt "$MAX_SHARDS" ]; then
  shards=$MAX_SHARDS
else
  shards=$n
fi
# Never more shards than ids: an empty shard would start a runner for nothing.
if [ "$n" -gt 0 ] && [ "$shards" -gt "$n" ]; then shards=$n; fi

if [ "$mode" = env ]; then
  if [ "${PLAN_SHARDS-}" != "$shards" ]; then
    echo "::error::the planned shard count does not match the inputs"
    exit 1
  fi
  if ! [[ "${SHARD-}" =~ ^[0-9]{1,2}$ ]] || [ "$SHARD" -lt 1 ] || [ "$SHARD" -gt "$shards" ]; then
    echo "::error::this shard is not in the planned matrix"
    exit 1
  fi
  if ! [[ "${JOB_TOTAL-}" =~ ^[0-9]{1,3}$ ]] || ! [[ "${JOB_INDEX-}" =~ ^[0-9]{1,3}$ ]] \
    || [ "$JOB_TOTAL" -ne "$shards" ] || [ "$((10#$JOB_INDEX + 1))" -ne "$SHARD" ]; then
    echo "::error::the job matrix does not match the planned shards"
    exit 1
  fi
  {
    echo "SURFACE_ONLY=$only"
    echo "SURFACE_SHARDS=$shards"
  } >>"$file"
else
  matrix=$(seq -s, 1 "$shards")
  {
    echo "shards=$shards"
    echo "matrix=[$matrix]"
  } >>"$file"
fi
