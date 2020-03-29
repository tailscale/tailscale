# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM golang:1.13-alpine AS build-env

WORKDIR /go/src/tailscale

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go install -v ./cmd/...

FROM alpine:3.11
RUN apk add --no-cache ca-certificates iptables
COPY --from=build-env /go/bin/* /usr/local/bin/

CMD ["/usr/local/bin/tailscaled", "--state=/var/lib/tailscale/tailscaled.state", "--socket=/var/run/tailscale/tailscaled.sock", "--port=41641"]


# docker run --network=host  --cap-add=NET_ADMIN --device /dev/net/tun:/dev/net/tun myusuf3/tailscale