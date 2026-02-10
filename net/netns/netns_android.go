// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package netns

import (
	"fmt"
	"sync"
	"syscall"

	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

var (
	androidProtectFuncMu sync.Mutex
	androidProtectFunc   func(fd int) error

	androidBindToNetworkFuncMu sync.Mutex
	androidBindToNetworkFunc   func(fd int) error
)

// If enabled, we skip the bind-to-network hook and let the routing table decide.
var bindToInterfaceByRouteEnv = envknob.RegisterBool("TS_BIND_TO_INTERFACE_BY_ROUTE")

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

// SetAndroidBindToNetworkFunc registers a func that Android provides that binds
// the socket FD to the currently selected underlying etwork
//
// A nil func disables the hook.
func SetAndroidBindToNetworkFunc(f func(fd int) error) {
	androidBindToNetworkFuncMu.Lock()
	defer androidBindToNetworkFuncMu.Unlock()
	androidBindToNetworkFunc = f
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

	// If route-based binding is enabled, we preserve the historical behavior:
	// protect from VPN loops, but do NOT force-bind to a particular Network.
	// This lets the OS routing table make per-destination decisions.
	useRoute := bindToInterfaceByRoute.Load() || bindToInterfaceByRouteEnv()

	err := c.Control(func(fd uintptr) {
		fdInt := int(fd)

		// Protect from VPN loops
		androidProtectFuncMu.Lock()
		pf := androidProtectFunc
		androidProtectFuncMu.Unlock()
		if pf != nil {
			if err := pf(fdInt); err != nil && sockErr == nil {
				sockErr = err
				return
			}
		}

		// Maybe bbind to currently active network
		if useRoute {
			return
		}

		androidBindToNetworkFuncMu.Lock()
		bf := androidBindToNetworkFunc
		androidBindToNetworkFuncMu.Unlock()
		if bf != nil {
			if err := bf(fdInt); err != nil && sockErr == nil {
				sockErr = err
				return
			}
		}
	})

	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}
