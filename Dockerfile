# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM golang:1.13-alpine AS build-env

WORKDIR /go/src/tailscale
COPY . .

RUN go get -d -v ./cmd/...
RUN go install -v ./cmd/...

FROM alpine:3.11
RUN apk add --no-cache ca-certificates
COPY --from=build-env /go/bin/tail* /usr/local/bin/
