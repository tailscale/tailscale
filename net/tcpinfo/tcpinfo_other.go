// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package tcpinfo

import (
	"net"
	"time"
)

func rttImpl(conn *net.TCPConn) (time.Duration, error) {
	return 0, ErrUnimplemented
}
