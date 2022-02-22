// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux
// +build !linux

package tstun

import "golang.zx2c4.com/wireguard/tun"

func setLinkAttrs(iface tun.Device) error {
	return nil
}
