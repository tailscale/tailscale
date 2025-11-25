#!/usr/bin/env bash
#
# This script sets up cigocacher, but should never fail the build if unsuccessful.
# It expects to run on a GitHub-hosted runner, and connects to cigocached over a
# private Azure network that is configured at the runner group level in GitHub.
#
# Usage: ./action.sh
# Inputs:
#   URL: The cigocached server URL.
# Outputs:
#   success: Whether cigocacher was set up successfully.

set -euo pipefail

if [ -z "${GITHUB_ACTIONS:-}" ]; then
    echo "This script is intended to run within GitHub Actions"
    exit 1
fi

if [ -z "$URL" ]; then
    echo "No cigocached URL is set, skipping cigocacher setup"
    exit 0
fi

JWT="$(curl -sSL -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=gocached" | jq -r .value)"
# cigocached serves a TLS cert with an FQDN, but DNS is based on VM name.
HOST_AND_PORT="${URL#http*://}"
FIRST_LABEL="${HOST_AND_PORT/.*/}"
# Save CONNECT_TO for later steps to use.
echo "CONNECT_TO=${HOST_AND_PORT}:${FIRST_LABEL}:" >> "${GITHUB_ENV}"
BODY="$(jq -n --arg jwt "$JWT" '{"jwt": $jwt}')"
CIGOCACHER_TOKEN="$(curl -sSL --connect-to "$HOST_AND_PORT:$FIRST_LABEL:" -H "Content-Type: application/json" "$URL/auth/exchange-token" -d "$BODY" | jq -r .access_token || true)"
if [ -z "$CIGOCACHER_TOKEN" ]; then
    echo "Failed token exchange with cigocached, skipping cigocacher setup"
    exit 0
fi

# Wait until we successfully auth before building cigocacher to ensure we know
# it's worth building.
# TODO(tomhjp): bake cigocacher into runner image and use it for auth.
echo "Fetched cigocacher token successfully"
echo "::add-mask::${CIGOCACHER_TOKEN}"
echo "CIGOCACHER_TOKEN=${CIGOCACHER_TOKEN}" >> "${GITHUB_ENV}"

BIN_PATH="${RUNNER_TEMP:-/tmp}/cigocacher$(go env GOEXE)"

go build -o "${BIN_PATH}" ./cmd/cigocacher
echo "GOCACHEPROG=${BIN_PATH} --cache-dir ${CACHE_DIR} --cigocached-url ${URL} --token ${CIGOCACHER_TOKEN}" >> "${GITHUB_ENV}"
echo "success=true" >> "${GITHUB_OUTPUT}"
