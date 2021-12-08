// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
