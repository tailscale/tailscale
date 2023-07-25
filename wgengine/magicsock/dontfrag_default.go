// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package magicsock

import (
	"errors"

	"tailscale.com/types/nettype"
)

func setDontFragment(pconn nettype.PacketConn, network string) (err error) {
	return errors.New("setting don't fragment bit not supported on this OS")
}
