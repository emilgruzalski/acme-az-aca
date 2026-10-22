#!/usr/bin/env bash
# End-to-end test: the app image against Pebble (ACME), challtestsrv (DNS) and
# mockkv (Key Vault + managed identity). See compose.yaml for the wiring.
#
#   e2e/run.sh            build the app image from the repo and run
#   E2E_IMAGE=img:tag E2E_SKIP_BUILD=1 e2e/run.sh   test an existing image
set -euo pipefail

cd "$(dirname "$0")"
export E2E_KV_PORT=${E2E_KV_PORT:-18081} E2E_APP_PORT=${E2E_APP_PORT:-18080}
compose() { docker compose "$@"; }

cleanup() {
  if [ "${failed:-0}" = 1 ]; then
    echo "--- app logs"; compose logs --no-color app || true
    echo "--- kv logs"; compose logs --no-color kv || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap 'failed=1' ERR
trap cleanup EXIT

step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; failed=1; exit 1; }
kv_state() { curl -fsS "http://127.0.0.1:$E2E_KV_PORT/e2e/state"; }
app_status() { curl -fsS "http://127.0.0.1:$E2E_APP_PORT/status"; }

# Logs are read into a variable before matching: piping them into grep -q
# under pipefail fails spuriously when grep exits early and docker gets SIGPIPE.
app_logs() { compose logs --no-color app 2>/dev/null || true; }
log_has() { grep -Eq "$1" <<<"$(app_logs)"; }

# wait_log PATTERN [TIMEOUT]: wait for the app's log to match an extended regex.
wait_log() {
  local deadline=$((SECONDS + ${2:-90}))
  until log_has "$1"; do
    [ $SECONDS -lt $deadline ] || fail "app log never matched: $1"
    sleep 1
  done
}

assert_log() {
  log_has "$1" || fail "app log does not contain: $1"
}

# start_app [VAR=value...]: (re)create the app container with extra settings.
start_app() {
  env "$@" docker compose up -d --no-build --force-recreate app >/dev/null
}

expect() { # expect DESCRIPTION JQ_FILTER JSON
  jq -e "$2" >/dev/null <<<"$3" || fail "$1: $(jq -c . <<<"$3")"
  echo "ok: $1"
}

compose down -v --remove-orphans >/dev/null 2>&1 || true
if [ "${E2E_SKIP_BUILD:-0}" != 1 ]; then
  step "build"
  compose build --quiet
else
  compose build --quiet kv
fi

step "start Pebble, DNS and mock Key Vault"
compose up -d dns pebble kv >/dev/null
deadline=$((SECONDS + 30))
until kv_state >/dev/null 2>&1; do
  [ $SECONDS -lt $deadline ] || fail "mockkv did not come up"
  sleep 1
done

step "1. first run issues a certificate and persists the ACME account key"
start_app
wait_log 'certificate renewed|certificate cycle failed'
assert_log 'certificate renewed'
state=$(kv_state)
expect "one import" '.imports == 1' "$state"
expect "cert covers both domains" '.certificates["acme-cert"] | sort == ["dev.example.test","prd.example.test"]' "$state"
expect "account key stored" '.secrets | index("acme-account-key") != null' "$state"
expect "/status healthy" '.healthy == true and .last_success != null' "$(app_status)"

step "2. restart reuses the account key and skips a valid certificate"
start_app
wait_log 'certificate still valid, skipping|certificate renewed|certificate cycle failed'
assert_log 'acme account key loaded from key vault'
assert_log 'certificate still valid, skipping'
expect "no new import" '.imports == 1' "$(kv_state)"

step "3. a domain missing from the certificate triggers a reissue"
domains3=dev.example.test,prd.example.test,api.example.test
start_app E2E_DOMAINS=$domains3
wait_log 'certificate renewed|certificate cycle failed'
assert_log 'does not cover all configured domains'
assert_log 'certificate renewed'
state=$(kv_state)
expect "second import" '.imports == 2' "$state"
expect "cert covers the new domain" '.certificates["acme-cert"] | index("api.example.test") != null' "$state"

step "4. a certificate inside the renewal window is renewed"
# Pebble certs are valid for 90 days, so a 100-day window is always hit.
start_app E2E_DOMAINS=$domains3 E2E_RENEW_BEFORE_DAYS=100
wait_log 'certificate renewed|certificate cycle failed'
assert_log 'certificate renewed'
expect "third import" '.imports == 3' "$(kv_state)"

step "5. a Key Vault outage aborts the cycle instead of reissuing"
compose stop kv >/dev/null
start_app E2E_DOMAINS=$domains3
wait_log 'certificate cycle failed|certificate renewed|still valid' 180
assert_log 'checking renewal: getting certificate'
if log_has 'Obtaining bundled SAN certificate'; then
  fail "a certificate was requested during the outage"
fi
echo "ok: no certificate requested"
expect "/status unhealthy" '.healthy == false and (.last_error | length) > 0' "$(app_status)"

step "6. SIGTERM shuts down cleanly"
compose stop app >/dev/null
wait_log 'shutting down' 10
code=$(docker inspect "$(compose ps -aq app)" --format '{{.State.ExitCode}}')
[ "$code" = 0 ] || fail "exit code $code"
echo "ok: exit code 0"

printf '\nPASS\n'
