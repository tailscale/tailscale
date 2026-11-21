#!/usr/bin/env bash
#
# This script sets up cigocacher, but should never fail the build if unsuccessful.
# It expects to run on a GitHub-hosted runner, and connects to cigocached over a
# private Azure network that is configured at the runner group level in GitHub.
#
# Usage: ./action.sh
# Inputs:
#   URL: The cigocached server URL.
#   HOST: The cigocached server host to dial.
#   BIN_DIR: Optional directory to find or build the cigocacher binary in.
# Outputs:
#   success: Whether cigocacher was set up successfully.

set -euo pipefail

if [ -z "${GITHUB_ACTIONS:-}" ]; then
    echo "This script is intended to run within GitHub Actions"
    exit 1
fi

if [ -z "${URL:-}" ]; then
    echo "No cigocached URL is set, skipping cigocacher setup"
    exit 0
fi

BIN_PATH="$(PATH="$PATH:$HOME/bin" command -v cigocacher || true)"
if [ -z "${BIN_PATH}" ]; then
  EXE=""
  if [ "${RUNNER_OS:-}" = "Windows" ]; then
    EXE=".exe"
  fi
  BIN_PATH="${BIN_DIR:-${RUNNER_TEMP:-/tmp}}/cigocacher${EXE}"
fi
if [ -f "${BIN_PATH}" ]; then
  echo "Using cigocacher at ${BIN_PATH}"
else
  echo "cigocacher not found in PATH or cache, attempting to build or fetch it"

  GOPATH=$(command -v go || true)
  if [ -z "${GOPATH}" ]; then
    if [ ! -f "tool/go" ]; then
      echo "Go not available, unable to proceed"
      exit 1
    fi
    GOPATH="./tool/go"
  fi

  mkdir -p "$(dirname "${BIN_PATH}")"
  if [ -d "cmd/cigocacher" ]; then
    echo "cmd/cigocacher found locally, building from local source"
    "${GOPATH}" build -o "${BIN_PATH}" ./cmd/cigocacher
  else
    echo "cmd/cigocacher not found locally, fetching from tailscale.com/cmd/cigocacher"
    "${GOPATH}" build -o "${BIN_PATH}" tailscale.com/cmd/cigocacher
  fi
fi

CIGOCACHER_TOKEN="$("${BIN_PATH}" --auth --cigocached-url "${URL}" --cigocached-host "${HOST}" )"
if [ -z "${CIGOCACHER_TOKEN:-}" ]; then
    echo "Failed to fetch cigocacher token, skipping cigocacher setup"
    exit 0
fi

echo "Fetched cigocacher token successfully"
echo "::add-mask::${CIGOCACHER_TOKEN}"

echo "GOCACHEPROG=${BIN_PATH} --cache-dir ${CACHE_DIR} --cigocached-url ${URL} --cigocached-host ${HOST} --token ${CIGOCACHER_TOKEN}" >> "${GITHUB_ENV}"
echo "success=true" >> "${GITHUB_OUTPUT}"
