// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"net"

	"github.com/akutz/memconn"
)

const memName = "Tailscale-IPN"

func listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	ln, err := memconn.Listen("memu", memName)
	return ln, 1, err
}

func connect(_ *ConnectionStrategy) (net.Conn, error) {
	return memconn.Dial("memu", memName)
}
