// Package uring provides a net.PacketConn and tun.Device that use io_uring for I/O.
package uring

import "runtime"

// This file contains code shared across all platforms.

// Available reports whether io_uring is available on this machine.
// If Available reports false, no other package uring APIs should be called.
func Available() bool {
	return runtime.GOOS == "linux"
}
