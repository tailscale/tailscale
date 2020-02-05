#!/bin/sh
# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e
redo-ifchange build
docker run --cap-add=NET_ADMIN \
	--device=/dev/net/tun:/dev/net/tun \
	-it tailscale
