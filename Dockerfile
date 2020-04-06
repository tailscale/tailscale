# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

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


FROM golang:1.14-alpine AS build-env

WORKDIR /go/src/tailscale

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go install -v ./cmd/...

FROM alpine:3.11
RUN apk add --no-cache ca-certificates iptables
COPY --from=build-env /go/bin/* /usr/local/bin/
