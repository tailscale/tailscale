// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package tstun

import "github.com/tailscale/wireguard-go/tun"

func setLinkAttrs(iface tun.Device) error {
	return nil
}
