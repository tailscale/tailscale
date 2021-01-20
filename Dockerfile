# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

############################################################################
#
# WARNING: Tailscale is not yet officially supported in Docker,
# Kubernetes, etc.
#
# It might work, but we don't regularly test it, and it's not as polished as
# our currently supported platforms. This is provided for people who know
# how Tailscale works and what they're doing.
#
# Our tracking bug for officially support container use cases is:
#    https://github.com/tailscale/tailscale/issues/504
#
# Also, see the various bugs tagged "containers":
#    https://github.com/tailscale/tailscale/labels/containers
#
############################################################################

# This Dockerfile includes all the tailscale binaries.
#
# To build the Dockerfile:
#
#     $ docker build -t tailscale:tailscale .
#
# To run the tailscaled agent:
#
#     $ docker run -d --name=tailscaled -v /var/lib:/var/lib -v /dev/net/tun:/dev/net/tun --network=host --privileged tailscale:tailscale tailscaled
#
# To then log in:
#
#     $ docker exec tailscaled tailscale up
#
# To see status:
#
#     $ docker exec tailscaled tailscale status


FROM golang:1.15-alpine AS build-env

WORKDIR /go/src/tailscale

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

ARG goflags_arg # default intentionally unset
ENV GOFLAGS=$goflags_arg

RUN go install -v ./cmd/...

FROM alpine:3.11
RUN apk add --no-cache ca-certificates iptables iproute2
COPY --from=build-env /go/bin/* /usr/local/bin/
