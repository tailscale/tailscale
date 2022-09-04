# Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

#! /bin/sh

export PATH=$PATH:/tailscale/bin

TS_AUTH_KEY="${TS_AUTH_KEY:-}"
TS_ROUTES="${TS_ROUTES:-}"
TS_DEST_IP="${TS_DEST_IP:-}"
TS_EXTRA_ARGS="${TS_EXTRA_ARGS:-}"
TS_USERSPACE="${TS_USERSPACE:-true}"
TS_STATE_DIR="${TS_STATE_DIR:-}"
TS_ACCEPT_DNS="${TS_ACCEPT_DNS:-false}"
TS_KUBE_SECRET="${TS_KUBE_SECRET:-tailscale}"
TS_SOCKS5_SERVER="${TS_SOCKS5_SERVER:-}"
TS_OUTBOUND_HTTP_PROXY_LISTEN="${TS_OUTBOUND_HTTP_PROXY_LISTEN:-}"
TS_TAILSCALED_EXTRA_ARGS="${TS_TAILSCALED_EXTRA_ARGS:-}"

set -e

TAILSCALED_ARGS="--socket=/tmp/tailscaled.sock"

if [[ ! -z "${KUBERNETES_SERVICE_HOST}" ]]; then
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --state=kube:${TS_KUBE_SECRET} --statedir=${TS_STATE_DIR:-/tmp}"
elif [[ ! -z "${TS_STATE_DIR}" ]]; then
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --statedir=${TS_STATE_DIR}"
else
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --state=mem: --statedir=/tmp"
fi

if [[ "${TS_USERSPACE}" == "true" ]]; then
  if [[ ! -z "${TS_DEST_IP}" ]]; then
    echo "IP forwarding is not supported in userspace mode"
    exit 1
  fi
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --tun=userspace-networking"
else
  if [[ ! -d /dev/net ]]; then
    mkdir -p /dev/net
  fi

  if [[ ! -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200
  fi
fi

if [[ ! -z "${TS_SOCKS5_SERVER}" ]]; then
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --socks5-server ${TS_SOCKS5_SERVER}"
fi

if [[ ! -z "${TS_OUTBOUND_HTTP_PROXY_LISTEN}" ]]; then
  TAILSCALED_ARGS="${TAILSCALED_ARGS} --outbound-http-proxy-listen ${TS_OUTBOUND_HTTP_PROXY_LISTEN}"
fi

if [[ ! -z "${TS_TAILSCALED_EXTRA_ARGS}" ]]; then
  TAILSCALED_ARGS="${TAILSCALED_ARGS} ${TS_TAILSCALED_EXTRA_ARGS}"
fi

handler() {
  echo "Caught SIGINT/SIGTERM, shutting down tailscaled"
  kill -s SIGINT $PID
  wait ${PID}
}

echo "Starting tailscaled"
tailscaled ${TAILSCALED_ARGS} &
PID=$!
trap handler SIGINT SIGTERM

UP_ARGS="--accept-dns=${TS_ACCEPT_DNS}"
if [[ ! -z "${TS_ROUTES}" ]]; then
  UP_ARGS="--advertise-routes=${TS_ROUTES} ${UP_ARGS}"
fi
if [[ ! -z "${TS_AUTH_KEY}" ]]; then
  UP_ARGS="--authkey=${TS_AUTH_KEY} ${UP_ARGS}"
fi
if [[ ! -z "${TS_EXTRA_ARGS}" ]]; then
  UP_ARGS="${UP_ARGS} ${TS_EXTRA_ARGS:-}"
fi

echo "Running tailscale up"
tailscale --socket=/tmp/tailscaled.sock up ${UP_ARGS}

if [[ ! -z "${TS_DEST_IP}" ]]; then
  echo "Adding iptables rule for DNAT"
  iptables -t nat -I PREROUTING -d "$(tailscale --socket=/tmp/tailscaled.sock ip -4)" -j DNAT --to-destination "${TS_DEST_IP}"
fi

echo "Waiting for tailscaled to exit"
wait ${PID}