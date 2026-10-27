// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !ts_omit_serve

package ipnlocal

import (
	"context"
	"net"
)

// dialServeUnixSocketSafe dials socketPath directly. This platform has no
// openat2(2) equivalent, so swapping the path can still retarget the
// connect. The caller re-checks the connected peer.
func (b *LocalBackend) dialServeUnixSocketSafe(ctx context.Context, socketPath string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
}
