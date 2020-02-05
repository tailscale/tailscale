# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Build with: docker build -t tailcontrol-alpine .
# Run with: docker run --cap-add=NET_ADMIN --device=/dev/net/tun:/dev/net/tun -it tailcontrol-alpine

FROM debian:stretch-slim

RUN apt-get update && apt-get -y install iproute2 iptables
RUN apt-get -y install ca-certificates
RUN apt-get -y install nginx-light

COPY relaynode /

# tailcontrol -tun=wg0 -dbdir=$HOME/taildb >> tailcontrol.log 2>&1 &
CMD ["/relaynode", "-R", "--config", "relay.conf"]
