#!/usr/bin/env bash
# Rust ACME client test suite runner: runs the mocked `cargo test` suite for
# rust/acmebot-acme, then spins up a local Pebble CA + pebble-challtestsrv and
# drives a real certificate issuance through the client against it.
#
# Run it locally before/after touching rust/acmebot-acme, and in CI on every
# change under rust/acmebot-acme. See CONTEXT.md for background on why Pebble
# contract testing is used alongside the mocked unit/integration tests.
#
# Usage:
#   scripts/ci/pebble-acme-test.sh [options]
#
# Options:
#   --skip-mocked-tests   Skip `cargo test` (mocked, no Pebble needed)
#   --skip-parity         Skip the live Pebble issuance run
#   --keep-pebble         Leave Pebble/challtestsrv running on exit (default: stop them)
#   -h, --help            Show this help
#
# Environment overrides:
#   PEBBLE_VERSION   Pebble release tag to install (default: 2.10.1)
#   PEBBLE_DIR       Install directory (default: <repo>/.tools/pebble)
set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SKIP_MOCKED_TESTS=0
SKIP_PARITY=0
KEEP_PEBBLE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-mocked-tests) SKIP_MOCKED_TESTS=1 ;;
    --skip-parity) SKIP_PARITY=1 ;;
    --keep-pebble) KEEP_PEBBLE=1 ;;
    -h|--help)
      sed -n '2,21p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PEBBLE_VERSION="${PEBBLE_VERSION:-2.10.1}"
PEBBLE_DIR="${PEBBLE_DIR:-$REPO_ROOT/.tools/pebble}"
PEBBLE_BIN="$PEBBLE_DIR/pebble-bin/pebble"
CHALLTESTSRV_BIN="$PEBBLE_DIR/challtestsrv-bin/pebble-challtestsrv"
PEBBLE_CONFIG="$PEBBLE_DIR/test/config/pebble-config.json"

RESULTS=()   # "label:pass" or "label:fail" entries, printed in the final summary
FAILED=0

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✘\033[0m %s\n' "$*"; }

record() {
  local label="$1" code="$2"
  if [[ "$code" -eq 0 ]]; then
    ok "$label"
    RESULTS+=("$label:pass")
  else
    fail "$label (exit $code)"
    RESULTS+=("$label:fail")
    FAILED=1
  fi
}

# ---------------------------------------------------------------------------
# Pebble install (idempotent — skipped if binaries already present)
# ---------------------------------------------------------------------------
detect_platform() {
  local os arch
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
  echo "${os}-${arch}"
}

install_pebble() {
  if [[ -x "$PEBBLE_BIN" && -x "$CHALLTESTSRV_BIN" && -f "$PEBBLE_CONFIG" ]]; then
    log "Pebble already installed at $PEBBLE_DIR (skipping download)"
    return
  fi

  local platform
  platform="$(detect_platform)"
  log "Installing Pebble v${PEBBLE_VERSION} (${platform}) into $PEBBLE_DIR"

  mkdir -p "$PEBBLE_DIR/pebble-bin" "$PEBBLE_DIR/challtestsrv-bin"

  local base="https://github.com/letsencrypt/pebble/releases/download/v${PEBBLE_VERSION}"
  curl -sSfL "${base}/pebble-${platform}.tar.gz" \
    | tar -xz -C "$PEBBLE_DIR/pebble-bin" --strip-components=3 \
      "pebble-${platform}/${platform%-*}/${platform#*-}/pebble"
  curl -sSfL "${base}/pebble-challtestsrv-${platform}.tar.gz" \
    | tar -xz -C "$PEBBLE_DIR/challtestsrv-bin" --strip-components=3 \
      "pebble-challtestsrv-${platform}/${platform%-*}/${platform#*-}/pebble-challtestsrv"

  # chmod can transiently fail with EPERM immediately after extraction on some
  # filesystems (observed on virtiofs-backed sandboxes) before the write is
  # fully committed; retry briefly rather than failing the whole install.
  local attempt
  for attempt in 1 2 3 4 5; do
    if chmod +x "$PEBBLE_BIN" "$CHALLTESTSRV_BIN" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
  [[ -x "$PEBBLE_BIN" && -x "$CHALLTESTSRV_BIN" ]] || { echo "Failed to make Pebble binaries executable" >&2; exit 1; }

  if [[ ! -f "$PEBBLE_CONFIG" ]]; then
    log "Fetching Pebble test config + certs from source tarball"
    curl -sSfL "https://github.com/letsencrypt/pebble/archive/refs/tags/v${PEBBLE_VERSION}.tar.gz" \
      | tar -xz -C "$PEBBLE_DIR" --strip-components=1 \
        "pebble-${PEBBLE_VERSION}/test"
  fi
}

# ---------------------------------------------------------------------------
# Pebble process lifecycle
# ---------------------------------------------------------------------------
PEBBLE_PID=""
CHALLTESTSRV_PID=""

start_pebble() {
  log "Starting pebble-challtestsrv (DNS-01 only) and pebble"
  "$CHALLTESTSRV_BIN" \
    -http01 "" -https01 "" -tlsalpn01 "" \
    -dnsserver ":8053" -management ":8055" \
    > "$PEBBLE_DIR/challtestsrv.log" 2>&1 &
  CHALLTESTSRV_PID=$!

  ( cd "$PEBBLE_DIR" && "$PEBBLE_BIN" \
      -config "$PEBBLE_CONFIG" -dnsserver 127.0.0.1:8053 \
      > "$PEBBLE_DIR/pebble.log" 2>&1 ) &
  PEBBLE_PID=$!

  log "Waiting for Pebble directory to become ready..."
  local attempt
  for attempt in $(seq 1 30); do
    if curl -sk --max-time 1 https://127.0.0.1:14000/dir > /dev/null 2>&1; then
      ok "Pebble directory is up (after ${attempt}s)"
      return
    fi
    sleep 1
  done

  fail "Pebble directory did not become ready within 30s"
  cat "$PEBBLE_DIR/pebble.log" >&2 || true
  exit 1
}

stop_pebble() {
  if [[ "$KEEP_PEBBLE" -eq 1 ]]; then
    log "Leaving Pebble running (--keep-pebble): pids pebble=$PEBBLE_PID challtestsrv=$CHALLTESTSRV_PID"
    return
  fi
  log "Stopping Pebble/challtestsrv"
  [[ -n "$PEBBLE_PID" ]] && kill "$PEBBLE_PID" 2>/dev/null || true
  [[ -n "$CHALLTESTSRV_PID" ]] && kill "$CHALLTESTSRV_PID" 2>/dev/null || true
}
trap stop_pebble EXIT

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
if [[ "$SKIP_MOCKED_TESTS" -eq 0 ]]; then
  log "Running Rust test suite (mocked HTTP, no Pebble required)"
  set +e
  (cd "$REPO_ROOT/rust" && cargo test --workspace)
  record "cargo test" $?
  set -e
fi

if [[ "$SKIP_PARITY" -eq 0 ]]; then
  install_pebble
  start_pebble

  log "Issuing a certificate through the Rust client against Pebble"
  set +e
  (cd "$REPO_ROOT/rust" && cargo run --quiet --example pebble_issue -- rust-acme-test.pebble)
  record "cargo run --example pebble_issue" $?
  set -e
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "Summary"
for entry in "${RESULTS[@]}"; do
  label="${entry%%:*}"
  status="${entry##*:}"
  if [[ "$status" == "pass" ]]; then
    ok "$label"
  else
    fail "$label"
  fi
done

if [[ "$FAILED" -ne 0 ]]; then
  echo
  fail "One or more steps failed"
  exit 1
fi

echo
ok "All steps passed"
