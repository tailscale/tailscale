// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux
// +build !linux

package pidlisten

import "net"

func checkPIDLocal(conn net.Conn) (bool, error) {
	panic("not implemented")
}
