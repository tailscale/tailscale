# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# Note that this Dockerfile is currently NOT used to build any of the published
# Tailscale container images and may have drifted from the image build mechanism
# we use.
# Tailscale images are currently built using https://github.com/tailscale/mkctr,
# and the build script can be found in ./build_docker.sh.
#
#
# This Dockerfile includes all the tailscale binaries.
#
# To build the Dockerfile:
#
#     $ docker build -t tailscale/tailscale .
#
# To run the tailscaled agent:
#
#     $ docker run -d --name=tailscaled -v /var/lib:/var/lib -v /dev/net/tun:/dev/net/tun --network=host --privileged tailscale/tailscale tailscaled
#
# To then log in:
#
#     $ docker exec tailscaled tailscale up
#
# To see status:
#
#     $ docker exec tailscaled tailscale status


FROM golang:1.23-alpine AS build-env

WORKDIR /go/src/tailscale

COPY go.mod go.sum ./
RUN go mod download

# Pre-build some stuff before the following COPY line invalidates the Docker cache.
RUN go install \
    github.com/aws/aws-sdk-go-v2/aws \
    github.com/aws/aws-sdk-go-v2/config \
    gvisor.dev/gvisor/pkg/tcpip/adapters/gonet \
    gvisor.dev/gvisor/pkg/tcpip/stack \
    golang.org/x/crypto/ssh \
    golang.org/x/crypto/acme \
    github.com/coder/websocket \
    github.com/mdlayher/netlink

COPY . .

# see build_docker.sh
ARG VERSION_LONG=""
ENV VERSION_LONG=$VERSION_LONG
ARG VERSION_SHORT=""
ENV VERSION_SHORT=$VERSION_SHORT
ARG VERSION_GIT_HASH=""
ENV VERSION_GIT_HASH=$VERSION_GIT_HASH
ARG TARGETARCH

# Basic build-time metadata as defined at https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
LABEL org.opencontainers.image.title="Tailscale" \
    org.opencontainers.image.description="The easiest, most secure way to use WireGuard and 2FA." \
    org.opencontainers.image.version="$VERSION_SHORT" \
    org.opencontainers.image.revision="$VERSION_GIT_HASH" \
    org.opencontainers.image.url="https://tailscale.com" \
    org.opencontainers.image.documentation="https://tailscale.com/kb" \
    org.opencontainers.image.source="https://github.com/tailscale/tailscale" \
    org.opencontainers.image.licenses="BSD-3-Clause" \
    org.opencontainers.image.vendor="Tailscale Inc"

RUN GOARCH=$TARGETARCH go install -ldflags="\
      -X tailscale.com/version.longStamp=$VERSION_LONG \
      -X tailscale.com/version.shortStamp=$VERSION_SHORT \
      -X tailscale.com/version.gitCommitStamp=$VERSION_GIT_HASH" \
      -v ./cmd/tailscale ./cmd/tailscaled ./cmd/containerboot

FROM alpine:3.18
RUN apk add --no-cache ca-certificates iptables iproute2 ip6tables

COPY --from=build-env /go/bin/* /usr/local/bin/
# For compat with the previous run.sh, although ideally you should be
# using build_docker.sh which sets an entrypoint for the image.
RUN mkdir /tailscale && ln -s /usr/local/bin/containerboot /tailscale/run.sh
