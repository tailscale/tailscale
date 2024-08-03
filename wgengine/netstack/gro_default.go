// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package netstack

import (
	nsgro "gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

// gro wraps a gVisor GRO implementation. It exists solely to prevent iOS from
// importing said package (see _ios.go).
type gro struct {
	nsgro.GRO
}
