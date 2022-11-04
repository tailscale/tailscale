// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package tstun

import "golang.zx2c4.com/wireguard/tun"

func interfaceName(dev tun.Device) (string, error) {
	return dev.Name()
}
