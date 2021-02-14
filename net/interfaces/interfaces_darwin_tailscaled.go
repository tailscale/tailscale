// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,!redo,!ios
// (Exclude redo, because we don't want this code in the App Store
// version's sandbox, where it won't work, and also don't want it on
// iOS. This is just for utun-using non-sandboxed cmd/tailscaled on macOS.

package interfaces

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

func DefaultRouteInterface() (string, error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return "", err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return "", err
	}
	return iface.Name, nil
}

func DefaultRouteInterfaceIndex() (int, error) {
	// $ netstat -nr
	// Routing tables
	// Internet:
	// Destination        Gateway            Flags        Netif Expire
	// default            10.0.0.1           UGSc           en0         <-- want this one
	// default            10.0.0.1           UGScI          en1

	// From man netstat:
	// U       RTF_UP           Route usable
	// G       RTF_GATEWAY      Destination requires forwarding by intermediary
	// S       RTF_STATIC       Manually added
	// c       RTF_PRCLONING    Protocol-specified generate new routes on use
	// I       RTF_IFSCOPE      Route is associated with an interface scope

	rib, err := route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
	if err != nil {
		return 0, fmt.Errorf("FetchRIB: %w", err)
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		return 0, fmt.Errorf("Parse: %w", err)
	}
	indexSeen := map[int]int{} // index => count
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		const RTF_GATEWAY = 0x2
		const RTF_IFSCOPE = 0x1000000
		if rm.Flags&RTF_GATEWAY == 0 {
			continue
		}
		if rm.Flags&RTF_IFSCOPE != 0 {
			continue
		}
		indexSeen[rm.Index]++
	}
	if len(indexSeen) == 0 {
		return 0, errors.New("no gateway index found")
	}
	if len(indexSeen) == 1 {
		for idx := range indexSeen {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("ambiguous gateway interfaces found: %v", indexSeen)
}
