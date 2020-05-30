// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// tailscaleBypassMark is the mark indicating that packets originating
// from a socket should bypass Tailscale-managed routes during routing
// table lookups.
//
// Keep this in sync with tailscaleBypassMark in
// wgengine/router/router_linux.go.
const tailscaleBypassMark = 0x20000

// control marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func control(network, address string, c syscall.RawConn) error {
	if skipPrivileged.Get() {
		// We can't set socket marks without CAP_NET_ADMIN on linux,
		// skip as requested.
		return nil
	}

	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tailscaleBypassMark)
	})
	// Before returning some fatal error, see if we're just a regular user
	// running cmd/tailscale (presumably netcheck) and ignore the error if so.
	if (err != nil || controlErr != nil) && os.Getuid() != 0 {
		if v, _ := os.Executable(); filepath.Base(v) == "tailscale" {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("setting socket mark: %w", err)
	}
	if controlErr != nil {
		return fmt.Errorf("setting socket mark: %w", controlErr)
	}
	return nil
}
