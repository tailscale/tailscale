// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package pidlisten implements a TCP listener that only
// accepts connections from the current process.
package pidlisten

import (
	"fmt"
	"net"
)

type listener struct {
	ln net.Listener
}

func (pln *listener) Accept() (net.Conn, error) {
	for {
		conn, err := pln.ln.Accept()
		if err != nil {
			return nil, err
		}
		ok, err := checkPIDLocal(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("pidlisten: %w", err)
		}
		if !ok {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

func (pln *listener) Close() error {
	return pln.ln.Close()
}

func (pln *listener) Addr() net.Addr {
	return pln.ln.Addr()
}
