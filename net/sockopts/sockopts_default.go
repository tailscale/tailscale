// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package sockopts

import (
	"tailscale.com/types/nettype"
)

// SetBufferSize sets pconn's buffer to size for direction. size may be silently
// capped depending on platform.
//
// errForce is only relevant for Linux, and will always be nil otherwise,
// but we maintain a consistent cross-platform API.
//
// If pconn is not a [*net.UDPConn], then SetBufferSize is no-op.
func SetBufferSize(pconn nettype.PacketConn, direction BufferDirection, size int) (errForce error, errPortable error) {
	return nil, portableSetBufferSize(pconn, direction, size)
}
