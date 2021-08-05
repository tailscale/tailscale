// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package tstun

import (
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/types/logger"
)

// Dummy implementation that does nothing.
func waitInterfaceUp(iface tun.Device, timeout time.Duration, logf logger.Logf) error {
	return nil
}
