// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package netns

import (
	"fmt"
	"sync"
	"syscall"

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var (
	androidProtectFuncMu sync.Mutex
	androidProtectFunc   func(fd int) error
)

// UseSocketMark reports whether SO_MARK is in use. Android does not use SO_MARK.
func UseSocketMark() bool {
	return false
}

// SetAndroidProtectFunc register a func that Android provides that JNI calls into
// https://developer.android.com/reference/android/net/VpnService#protect(int)
// which is documented as:
//
// "Protect a socket from VPN connections. After protecting, data sent
// through this socket will go directly to the underlying network, so
// its traffic will not be forwarded through the VPN. This method is
// useful if some connections need to be kept outside of VPN. For
// example, a VPN tunnel should protect itself if its destination is
// covered by VPN routes. Otherwise its outgoing packets will be sent
// back to the VPN interface and cause an infinite loop. This method
// will fail if the application is not prepared or is revoked."
//
// A nil func disables the use the hook.
//
// This indirection is necessary because this is the supported, stable
// interface to use on Android, and doing the sockopts to set the
// fwmark return errors on Android. The actual implementation of
// VpnService.protect ends up doing an IPC to another process on
// Android, asking for the fwmark to be set.
func SetAndroidProtectFunc(f func(fd int) error) {
	androidProtectFuncMu.Lock()
	defer androidProtectFuncMu.Unlock()
	androidProtectFunc = f
}

func control(logger.Logf, *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return controlC
}

// controlC marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func controlC(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		androidProtectFuncMu.Lock()
		f := androidProtectFunc
		androidProtectFuncMu.Unlock()
		if f != nil {
			sockErr = f(int(fd))
		}
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}
