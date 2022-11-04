// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ts_macext && (darwin || ios)

package resolver

import (
	"errors"
	"net"

	"tailscale.com/net/netns"
	"tailscale.com/wgengine/monitor"
)

func init() {
	initListenConfig = initListenConfigNetworkExtension
}

func initListenConfigNetworkExtension(nc *net.ListenConfig, mon *monitor.Mon, tunName string) error {
	nif, ok := mon.InterfaceState().Interface[tunName]
	if !ok {
		return errors.New("utun not found")
	}
	return netns.SetListenConfigInterfaceIndex(nc, nif.Interface.Index)
}
