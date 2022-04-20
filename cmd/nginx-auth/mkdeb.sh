#!/usr/bin/env bash

set -e

CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o tailscale.nginx-auth .

VERSION=0.1.1

mkpkg \
    --out=tailscale-nginx-auth-${VERSION}-amd64.deb \
    --name=tailscale-nginx-auth \
    --version=${VERSION} \
    --type=deb \
    --arch=amd64 \
    --postinst=deb/postinst.sh \
    --postrm=deb/postrm.sh \
    --prerm=deb/prerm.sh \
    --description="Tailscale NGINX authentication protocol handler" \
    --files=./tailscale.nginx-auth:/usr/sbin/tailscale.nginx-auth,./tailscale.nginx-auth.socket:/lib/systemd/system/tailscale.nginx-auth.socket,./tailscale.nginx-auth.service:/lib/systemd/system/tailscale.nginx-auth.service,./README.md:/usr/share/tailscale/nginx-auth/README.md

mkpkg \
    --out=tailscale-nginx-auth-${VERSION}-amd64.rpm \
    --name=tailscale-nginx-auth \
    --version=${VERSION} \
    --type=rpm \
    --arch=amd64 \
    --postinst=rpm/postinst.sh \
    --postrm=rpm/postrm.sh \
    --prerm=rpm/prerm.sh \
    --description="Tailscale NGINX authentication protocol handler" \
    --files=./tailscale.nginx-auth:/usr/sbin/tailscale.nginx-auth,./tailscale.nginx-auth.socket:/lib/systemd/system/tailscale.nginx-auth.socket,./tailscale.nginx-auth.service:/lib/systemd/system/tailscale.nginx-auth.service,./README.md:/usr/share/tailscale/nginx-auth/README.md
