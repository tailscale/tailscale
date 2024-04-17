// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"net"

	"github.com/akutz/memconn"
)

const memName = "Tailscale-IPN"

func listen(path string) (net.Listener, error) {
	return memconn.Listen("memu", memName)
}

func connect(_ string) (net.Conn, error) {
	return memconn.Dial("memu", memName)
}
