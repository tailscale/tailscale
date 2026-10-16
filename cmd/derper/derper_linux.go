// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// controlTCPSaveSyn sets TCP_SAVE_SYN on a listening socket when --tcp-save-syn
// is enabled. Accepted connections inherit the option.
func controlTCPSaveSyn(network string, c syscall.RawConn) error {
	if !*tcpSaveSyn {
		return nil
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("--tcp-save-syn: unsupported network: %s", network)
	}
	var err error
	if e := c.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
	}); e != nil {
		return e
	}
	return err
}
