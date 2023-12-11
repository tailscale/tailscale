# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

############################################################################
#
# WARNING: Tailscale is not yet officially supported in container
# environments, such as Docker and Kubernetes. Though it should work, we
# don't regularly test it, and we know there are some feature limitations.
#
# See current bugs tagged "containers":
#    https://github.com/tailscale/tailscale/labels/containers
#
############################################################################

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


FROM golang:1.21-alpine AS build-env

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
    nhooyr.io/websocket \
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
