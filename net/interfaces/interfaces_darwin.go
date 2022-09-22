// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/netaddr"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return d, err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return d, err
	}
	d.InterfaceName = iface.Name
	d.InterfaceIndex = idx
	return d, nil
}

// fetchRoutingTable calls route.FetchRIB, fetching NET_RT_DUMP2.
func fetchRoutingTable() (rib []byte, err error) {
	return route.FetchRIB(syscall.AF_UNSPEC, syscall.NET_RT_DUMP2, 0)
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

	rib, err := fetchRoutingTable()
	if err != nil {
		return 0, fmt.Errorf("route.FetchRIB: %w", err)
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
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

// InterfaceIndexFor returns the interface index that we should bind to in
// order to send traffic to the provided address.
func InterfaceIndexFor(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("creating AF_ROUTE socket: %w", err)
	}
	defer unix.Close(fd)

	var routeAddr route.Addr
	if addr.Is4() {
		routeAddr = &route.Inet4Addr{IP: addr.As4()}
	} else {
		routeAddr = &route.Inet6Addr{IP: addr.As16()}
	}

	rm := route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST: routeAddr,
		},
	}
	b, err := rm.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshaling RouteMessage: %w", err)
	}
	_, err = unix.Write(fd, b)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w")
	}
	var buf [2048]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return 0, fmt.Errorf("reading message: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	if len(msgs) == 0 {
		return 0, fmt.Errorf("no messages")
	}

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Version < 3 || rm.Version > 5 || rm.Type != unix.RTM_GET {
			continue
		}
		if len(rm.Addrs) < unix.RTAX_GATEWAY {
			continue
		}

		laddr, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok {
			continue
		}

		return laddr.Index, nil
	}

	return 0, fmt.Errorf("no valid address found")
}

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPDarwinFetchRIB
}

func likelyHomeRouterIPDarwinFetchRIB() (ret netip.Addr, ok bool) {
	rib, err := fetchRoutingTable()
	if err != nil {
		log.Printf("routerIP/FetchRIB: %v", err)
		return ret, false
	}
	msgs, err := route.ParseRIB(syscall.NET_RT_IFLIST2, rib)
	if err != nil {
		log.Printf("routerIP/ParseRIB: %v", err)
		return ret, false
	}
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
		if len(rm.Addrs) > unix.RTAX_GATEWAY {
			dst4, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
			if !ok || dst4.IP != ([4]byte{0, 0, 0, 0}) {
				// Expect 0.0.0.0 as DST field.
				continue
			}
			gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
			if !ok {
				continue
			}
			return netaddr.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]), true
		}
	}

	return ret, false
}
