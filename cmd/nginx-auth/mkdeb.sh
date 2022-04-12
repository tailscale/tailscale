#!/usr/bin/env bash

set -e

CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o tailscale.nginx-auth .

mkpkg \
    --out tailscale-nginx-auth-0.1.0-amd64.deb \
    --name=tailscale-nginx-auth \
    --version=0.1.0 \
    --type=deb\
    --arch=amd64 \
    --description="Tailscale NGINX authentication protocol handler" \
    --files=./tailscale.nginx-auth:/usr/sbin/tailscale.nginx-auth,./tailscale.nginx-auth.socket:/lib/systemd/system/tailscale.nginx-auth.socket,./tailscale.nginx-auth.service:/lib/systemd/system/tailscale.nginx-auth.service

mkpkg \
    --out tailscale-nginx-auth-0.1.0-amd64.rpm \
    --name=tailscale-nginx-auth \
    --version=0.1.0 \
    --type=rpm \
    --arch=amd64 \
    --description="Tailscale NGINX authentication protocol handler" \
    --files=./tailscale.nginx-auth:/usr/sbin/tailscale.nginx-auth,./tailscale.nginx-auth.socket:/lib/systemd/system/tailscale.nginx-auth.socket,./tailscale.nginx-auth.service:/lib/systemd/system/tailscale.nginx-auth.service
