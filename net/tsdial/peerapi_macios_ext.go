// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file's built on iOS and on two of three macOS build variants:
// the two GUI variants that both use Extensions (Network Extension
// and System Extension). It's not used on tailscaled-on-macOS.

//go:build ts_macext && (darwin || ios)

package tsdial

import (
	"errors"
	"net"
	"syscall"

	"tailscale.com/net/netns"
)

func init() {
	peerDialControlFunc = peerDialControlFuncNetworkExtension
}

func peerDialControlFuncNetworkExtension(d *Dialer) func(network, address string, c syscall.RawConn) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	index := -1
	if x, ok := d.interfaceIndexLocked(d.tunName); ok {
		index = x
	}
	var lc net.ListenConfig
	netns.SetListenConfigInterfaceIndex(&lc, index)
	return func(network, address string, c syscall.RawConn) error {
		if index == -1 {
			return errors.New("failed to find TUN interface to bind to")
		}
		return lc.Control(network, address, c)
	}
}
