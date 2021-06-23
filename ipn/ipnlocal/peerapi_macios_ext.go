// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,ts_macext ios,ts_macext

package ipnlocal

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
)

func init() {
	initListenConfig = initListenConfigNetworkExtension
	peerDialControlFunc = peerDialControlFuncNetworkExtension
}

// initListenConfigNetworkExtension configures nc for listening on IP
// through the iOS/macOS Network/System Extension (Packet Tunnel
// Provider) sandbox.
func initListenConfigNetworkExtension(nc *net.ListenConfig, ip netaddr.IP, st *interfaces.State, tunIfName string) error {
	tunIf, ok := st.Interface[tunIfName]
	if !ok {
		return fmt.Errorf("no interface with name %q", tunIfName)
	}
	return netns.SetListenConfigInterfaceIndex(nc, tunIf.Index)
}

func peerDialControlFuncNetworkExtension(b *LocalBackend) func(network, address string, c syscall.RawConn) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.prevIfState
	pas := b.peerAPIServer
	index := -1
	if st != nil && pas != nil && pas.tunName != "" {
		if tunIf, ok := st.Interface[pas.tunName]; ok {
			index = tunIf.Index
		}
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
