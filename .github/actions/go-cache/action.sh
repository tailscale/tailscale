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

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BASE_CMD="${REPO_ROOT}/tool/cigocacher --cache-dir ${CACHE_DIR} --cigocached-url ${URL} --cigocached-host ${HOST}"

CIGOCACHER_TOKEN="$("${BASE_CMD}" --auth)"
if [ -z "${CIGOCACHER_TOKEN:-}" ]; then
    echo "Failed to fetch cigocacher token, skipping cigocacher setup"
    exit 0
fi

echo "Fetched cigocacher token successfully"
echo "::add-mask::${CIGOCACHER_TOKEN}"

echo "GOCACHEPROG=${BASE_CMD} --token ${CIGOCACHER_TOKEN}" >> "${GITHUB_ENV}"
echo "success=true" >> "${GITHUB_OUTPUT}"
