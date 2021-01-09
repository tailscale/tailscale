// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/wintun"
	"golang.org/x/sys/windows"
)

func init() {
	var err error
	tun.WintunPool, err = wintun.MakePool("Tailscale")
	if err != nil {
		panic(err)
	}
	guid, err := windows.GUIDFromString("{37217669-42da-4657-a55b-0d995d328250}")
	if err != nil {
		panic(err)
	}
	tun.WintunStaticRequestedGUID = &guid
}
