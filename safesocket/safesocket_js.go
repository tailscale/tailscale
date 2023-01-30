// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"net"

	"github.com/akutz/memconn"
)

const memName = "Tailscale-IPN"

func listen(path string) (net.Listener, error) {
	return memconn.Listen("memu", memName)
}

func connect(_ *ConnectionStrategy) (net.Conn, error) {
	return memconn.Dial("memu", memName)
}
