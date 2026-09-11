#!/usr/bin/env bash
# Distributed-path smoke test — drives a real `scan` run end to end through the deployed stack
# (nginx → api → Redis → Arq worker → per-host job → terminal state), asserting the two-pool
# supervisor path actually completes. Run this from a host that can reach the compose stack, against
# an IN-SCOPE target on your authorized internal network.
#
#   ./deploy/smoke.sh                       # against https://127.0.0.1:8443, target 127.0.0.1
#   BASE=https://nabu.internal:8443 TARGET=10.10.10.5 ./deploy/smoke.sh
#   SMOKE_UP=1 ./deploy/smoke.sh            # `docker compose up -d` first, then smoke
#
# Env knobs: BASE, ADMIN_EMAIL, ADMIN_PASSWORD, TARGET, TIMEOUT (s), SMOKE_UP=1.
# Exit 0 = the run reached a successful terminal state (done|partial); non-zero = failed/timeout.
set -euo pipefail

BASE="${BASE:-https://127.0.0.1:8443}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@nabu.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-changeme}"
TARGET="${TARGET:-127.0.0.1}"
TIMEOUT="${TIMEOUT:-600}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

for bin in curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "FAIL: '$bin' is required" >&2; exit 2; }
done

# curl through a self-signed cert (-k); carry the session cookie in a jar.
c() { curl -sk --cookie "$JAR" --cookie-jar "$JAR" "$@"; }
say() { printf '\033[36m▸ %s\033[0m\n' "$*"; }
die() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

if [[ "${SMOKE_UP:-0}" == "1" ]]; then
  say "docker compose up -d"
  docker compose -f "$(dirname "$0")/../docker-compose.yml" up -d
fi

# 1. readiness — DB + Redis + engine + workspace all green
say "waiting for $BASE/api/health/ready (timeout ${TIMEOUT}s)"
deadline=$(( $(date +%s) + TIMEOUT ))
until ready=$(c "$BASE/api/health/ready" | jq -r '.ready' 2>/dev/null) && [[ "$ready" == "true" ]]; do
  [[ $(date +%s) -ge $deadline ]] && die "API never became ready"
  sleep 3
done
say "ready: $(c "$BASE/api/health/ready" | jq -c '.checks')"

# 2. sign in (session cookie lands in the jar)
code=$(c -o /dev/null -w '%{http_code}' -X POST "$BASE/api/auth/login" \
       -H 'Content-Type: application/json' \
       -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
[[ "$code" == "200" ]] || die "login returned HTTP $code (check ADMIN_EMAIL/ADMIN_PASSWORD)"
say "signed in as $ADMIN_EMAIL"

# 3. project + authorized scope
pid=$(c -X POST "$BASE/api/projects" -H 'Content-Type: application/json' \
      -d "{\"display_name\":\"smoke $(date +%H%M%S)\"}" | jq -r '.id')
[[ -n "$pid" && "$pid" != "null" ]] || die "could not create project"
c -X POST "$BASE/api/projects/$pid/scope" -H 'Content-Type: application/json' \
  -d "{\"target\":\"$TARGET\"}" >/dev/null
say "project $pid scoped to $TARGET"

# 4. start a real scan run (goes onto the Arq worker pool when NABU_USE_ARQ=true)
run_id=$(c -X POST "$BASE/api/projects/$pid/runs" -H 'Content-Type: application/json' \
         -d "{\"target\":\"$TARGET\",\"kind\":\"scan\"}" | jq -r '.run_id')
[[ -n "$run_id" && "$run_id" != "null" ]] || die "could not start run"
say "run $run_id started (kind=scan)"

# 5. poll to a terminal state
deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  state=$(c "$BASE/api/runs/$run_id" | jq -r '.state')
  case "$state" in
    done|partial)      say "run reached '$state' ✓"; break ;;
    failed|cancelled)  die "run ended '$state' — check: docker compose logs worker" ;;
    *)                 [[ $(date +%s) -ge $deadline ]] && die "run stuck in '$state' after ${TIMEOUT}s"
                       printf '  … %s\n' "$state"; sleep 5 ;;
  esac
done

printf '\033[32mPASS: distributed scan path is healthy (run %s → %s)\033[0m\n' "$run_id" "$state"
