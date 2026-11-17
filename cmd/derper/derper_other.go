// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package main

import (
	"net"
	"syscall"

	"tailscale.com/derp/derpserver"
)

// controlTCPSaveSyn is a no-op on platforms without TCP_SAVE_SYN.
func controlTCPSaveSyn(network string, c syscall.RawConn) error { return nil }

func newTCPSaveSynListener(ln net.Listener, s *derpserver.Server) net.Listener { return ln }
