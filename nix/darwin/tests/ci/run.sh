#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# End-to-end test for the macOS Tailscale module.
# Runs Headscale on loopback, applies a nix-darwin config that defines
# two userspace tailscaled instances, and verifies each one authenticates
# against its own Headscale user without leaking state to the other.
#
# Designed for a clean macos-latest GitHub Actions runner. Safe to run
# locally on a Mac that already has Nix installed.

set -euo pipefail

readonly STATE_DIR="/tmp/ts-ci"
readonly HEADSCALE_LOG="${STATE_DIR}/headscale.log"
readonly TAILSCALE_LOG_DIR="${HOME}/Library/Logs"
readonly INSTANCES=(alpha beta)

# Pick the darwinConfiguration matching this host.
arch=$(uname -m)
case "$arch" in
  arm64)  readonly DARWIN_CFG="ci-mac-aarch64" ;;
  x86_64) readonly DARWIN_CFG="ci-mac-x86_64" ;;
  *) echo "unsupported arch $arch" >&2; exit 1 ;;
esac

log()  { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; dump_logs; exit 1; }

dump_logs() {
  # `>&2 2>/dev/null` redirects stdout to the original stderr, then
  # silences stderr — the opposite order silently sends everything to
  # /dev/null.
  printf '\n--- headscale.log (tail) ---\n' >&2
  tail -n 100 "$HEADSCALE_LOG" >&2 2>/dev/null || true
  for inst in "${INSTANCES[@]}"; do
    printf '\n--- Tailscale-%s.log (tail) ---\n' "$inst" >&2
    tail -n 100 "${TAILSCALE_LOG_DIR}/Tailscale-${inst}.log" >&2 2>/dev/null || true
  done
}

cleanup() {
  local rc=$?
  log "cleanup"
  for inst in "${INSTANCES[@]}"; do
    launchctl bootout "gui/$(id -u)" \
      "${HOME}/Library/LaunchAgents/com.tailscale.tailscaled-${inst}.plist" \
      2>/dev/null || true
    launchctl bootout "gui/$(id -u)" \
      "${HOME}/Library/LaunchAgents/com.tailscale.tailscale-${inst}-bootstrap.plist" \
      2>/dev/null || true
  done
  if [[ -n "${HEADSCALE_PID:-}" ]]; then
    kill "$HEADSCALE_PID" 2>/dev/null || true
    wait "$HEADSCALE_PID" 2>/dev/null || true
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

main() {
  log "workspace"
  mkdir -p "$STATE_DIR" "$TAILSCALE_LOG_DIR"

  # Build headscale and jq up front. Each subsequent invocation goes
  # directly to the resolved store-path binary — far cheaper than
  # spawning `nix shell` per call. Use the ^bin output selector since
  # jq is multi-output (bin + man + …) and `--print-out-paths` lists
  # every output otherwise.
  log "fetch headscale + jq"
  HEADSCALE=$(nix build --quiet --no-link --print-out-paths \
    'nixpkgs#headscale')/bin/headscale
  JQ=$(nix build --quiet --no-link --print-out-paths \
    'nixpkgs#jq^bin')/bin/jq

  log "start headscale"
  "$HEADSCALE" serve -c "${PWD}/headscale.yaml" \
    > "$HEADSCALE_LOG" 2>&1 &
  HEADSCALE_PID=$!

  log "wait for headscale"
  for _ in $(seq 1 60); do
    if "$HEADSCALE" -c "${PWD}/headscale.yaml" users list >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  "$HEADSCALE" -c "${PWD}/headscale.yaml" users list \
    >/dev/null 2>&1 || fail "headscale did not become ready"

  log "create users + preauth keys"
  for inst in "${INSTANCES[@]}"; do
    # Headscale 0.28's `preauthkeys create --user` expects a numeric ID,
    # not a name. Create the user, then look its ID up by name.
    "$HEADSCALE" -c "${PWD}/headscale.yaml" users create "$inst" >/dev/null
    user_id=$("$HEADSCALE" -c "${PWD}/headscale.yaml" users list --output json \
      | "$JQ" -r ".[] | select(.name==\"$inst\") | .id")
    [[ -n "$user_id" ]] || fail "could not resolve user id for $inst"
    key=$("$HEADSCALE" -c "${PWD}/headscale.yaml" \
      preauthkeys create --reusable --expiration 1h --user "$user_id" \
      --output json | "$JQ" -r .key)
    [[ -n "$key" ]] || fail "empty preauth key for $inst"
    printf '%s' "$key" > "${STATE_DIR}/${inst}.key"
    chmod 600 "${STATE_DIR}/${inst}.key"
  done

  log "apply nix-darwin config (${DARWIN_CFG})"
  # Recent nix-darwin requires system activation to run as root. Invoke
  # the user's `nix` (DeterminateSystems install path may not be on
  # root's default PATH) and preserve the env so flake-fetching and
  # cache lookups use the same daemon.
  nix_bin=$(command -v nix)
  sudo --preserve-env=HOME,USER \
    "$nix_bin" run --quiet github:LnL7/nix-darwin -- switch \
    --flake "${PWD}#${DARWIN_CFG}"

  # darwin-rebuild updates the system profile, but the running shell's
  # PATH was captured at startup. Pick up the freshly-installed CLI
  # wrappers (tailscale-alpha, tailscale-beta) before exercising them.
  user=$(id -un)
  export PATH="/run/current-system/sw/bin:/etc/profiles/per-user/${user}/bin:${PATH}"

  log "wait for LaunchAgents"
  for inst in "${INSTANCES[@]}"; do
    for _ in $(seq 1 60); do
      if launchctl print "gui/$(id -u)/com.tailscale.tailscaled-${inst}" \
        >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    launchctl print "gui/$(id -u)/com.tailscale.tailscaled-${inst}" \
      >/dev/null 2>&1 || fail "agent tailscaled-${inst} never loaded"
  done

  log "wait for daemon socket"
  for inst in "${INSTANCES[@]}"; do
    sock="${HOME}/Library/Caches/Tailscale-${inst}/tsd.sock"
    for _ in $(seq 1 60); do
      # `status` (no --json) exits non-zero before login, so we'd loop
      # forever. `--json` only checks that the backend is reachable.
      [[ -S "$sock" ]] && "tailscale-${inst}" status --json >/dev/null 2>&1 && break
      sleep 1
    done
    "tailscale-${inst}" status --json >/dev/null 2>&1 \
      || fail "${inst} daemon socket never became responsive"
  done

  # The module's bootstrap LaunchAgent should have run `tailscale up`
  # automatically on activation. In CI the launchctl gui domain doesn't
  # always cooperate when activation runs under sudo, so re-invoke `up`
  # explicitly — idempotent against an instance the bootstrap already
  # authenticated, and the canonical fallback for users debugging by
  # hand. The verify-Running step below catches both paths.
  log "authenticate instances"
  for inst in "${INSTANCES[@]}"; do
    key=$(cat "${STATE_DIR}/${inst}.key")
    "tailscale-${inst}" up --reset \
      --auth-key="$key" \
      --login-server=http://127.0.0.1:8080 \
      --hostname="ci-${inst}"
  done

  log "wait for BackendState=Running"
  for inst in "${INSTANCES[@]}"; do
    for _ in $(seq 1 120); do
      state=$("tailscale-${inst}" status --json 2>/dev/null \
        | "$JQ" -r '.BackendState' 2>/dev/null || true)
      [[ "$state" == "Running" ]] && break
      sleep 1
    done
    [[ "$state" == "Running" ]] || fail "${inst} stuck in state=${state:-<unset>}"
  done

  log "verify per-instance identity"
  alpha_user=$("tailscale-alpha" status --json | "$JQ" -r '.Self.UserID')
  beta_user=$("tailscale-beta"  status --json | "$JQ" -r '.Self.UserID')
  [[ -n "$alpha_user" && -n "$beta_user" ]] \
    || fail "missing Self.UserID on one of the instances"
  [[ "$alpha_user" != "$beta_user" ]] \
    || fail "alpha and beta share the same UserID (${alpha_user}) — isolation broken"

  log "verify socket isolation"
  for inst in "${INSTANCES[@]}"; do
    sock="${HOME}/Library/Caches/Tailscale-${inst}/tsd.sock"
    [[ -S "$sock" ]] || fail "socket missing: $sock"
  done

  log "verify state isolation"
  for inst in "${INSTANCES[@]}"; do
    state_file="${HOME}/Library/Application Support/Tailscale-${inst}/tailscaled.state"
    [[ -f "$state_file" ]] || fail "state file missing: $state_file"
  done

  alpha_state=$(shasum -a 256 "${HOME}/Library/Application Support/Tailscale-alpha/tailscaled.state" | awk '{print $1}')
  beta_state=$(shasum -a 256 "${HOME}/Library/Application Support/Tailscale-beta/tailscaled.state" | awk '{print $1}')
  [[ "$alpha_state" != "$beta_state" ]] \
    || fail "alpha and beta tailscaled.state are byte-identical — isolation broken"

  log "PASS"
}

main "$@"
