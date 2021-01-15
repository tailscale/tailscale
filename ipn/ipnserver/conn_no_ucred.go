// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux

package ipnserver

import (
	"net"

	"tailscale.com/types/logger"
)

func isReadonlyConn(c net.Conn, logf logger.Logf) bool {
	// Windows doesn't need/use this mechanism, at least yet. It
	// has a different last-user-wins auth model.

	// And on Darwin, we're not using it yet, as the Darwin
	// tailscaled port isn't yet done, and unix.Ucred and
	// unix.GetsockoptUcred aren't in x/sys/unix.

	// TODO(bradfitz): OpenBSD and FreeBSD should implement this too.
	// But their x/sys/unix package is different than Linux, so
	// I didn't include it for now.
	return false
}
