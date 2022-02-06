/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

// Package conn implements WireGuard's network connections.
package conn

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"strings"
)

// A ReceiveFunc receives a single inbound packet from the network.
// It writes the data into b. n is the length of the packet.
// ep is the remote endpoint.
type ReceiveFunc func(b []byte) (n int, ep Endpoint, err error)

// A Bind listens on a port for both IPv6 and IPv4 UDP traffic.
//
// A Bind interface may also be a PeekLookAtSocketFd or BindSocketToInterface,
// depending on the platform-specific implementation.
type Bind interface {
	// Open puts the Bind into a listening state on a given port and reports the actual
	// port that it bound to. Passing zero results in a random selection.
	// fns is the set of functions that will be called to receive packets.
	Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error)

	// Close closes the Bind listener.
	// All fns returned by Open must return net.ErrClosed after a call to Close.
	Close() error

	// SetMark sets the mark for each packet sent through this Bind.
	// This mark is passed to the kernel as the socket option SO_MARK.
	SetMark(mark uint32) error

	// Send writes a packet b to address ep.
	Send(b []byte, ep Endpoint) error

	// ParseEndpoint creates a new endpoint from a string.
	ParseEndpoint(s string) (Endpoint, error)
}

// BindSocketToInterface is implemented by Bind objects that support being
// tied to a single network interface. Used by wireguard-windows.
type BindSocketToInterface interface {
	BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error
	BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error
}

// PeekLookAtSocketFd is implemented by Bind objects that support having their
// file descriptor peeked at. Used by wireguard-android.
type PeekLookAtSocketFd interface {
	PeekLookAtSocketFd4() (fd int, err error)
	PeekLookAtSocketFd6() (fd int, err error)
}

// An Endpoint maintains the source/destination caching for a peer.
//
//	dst: the remote address of a peer ("endpoint" in uapi terminology)
//	src: the local address from which datagrams originate going to the peer
type Endpoint interface {
	ClearSrc()           // clears the source address
	SrcToString() string // returns the local source address (ip:port)
	DstToString() string // returns the destination address (ip:port)
	DstToBytes() []byte  // used for mac2 cookie calculations
	DstIP() net.IP
	SrcIP() net.IP
}

var (
	ErrBindAlreadyOpen   = errors.New("bind is already open")
	ErrWrongEndpointType = errors.New("endpoint type does not correspond with bind type")
)

func (fn ReceiveFunc) PrettyName() string {
	name := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	// 0. cheese/taco.beansIPv6.func12.func21218-fm
	name = strings.TrimSuffix(name, "-fm")
	// 1. cheese/taco.beansIPv6.func12.func21218
	if idx := strings.LastIndexByte(name, '/'); idx != -1 {
		name = name[idx+1:]
		// 2. taco.beansIPv6.func12.func21218
	}
	for {
		var idx int
		for idx = len(name) - 1; idx >= 0; idx-- {
			if name[idx] < '0' || name[idx] > '9' {
				break
			}
		}
		if idx == len(name)-1 {
			break
		}
		const dotFunc = ".func"
		if !strings.HasSuffix(name[:idx+1], dotFunc) {
			break
		}
		name = name[:idx+1-len(dotFunc)]
		// 3. taco.beansIPv6.func12
		// 4. taco.beansIPv6
	}
	if idx := strings.LastIndexByte(name, '.'); idx != -1 {
		name = name[idx+1:]
		// 5. beansIPv6
	}
	if name == "" {
		return fmt.Sprintf("%p", fn)
	}
	if strings.HasSuffix(name, "IPv4") {
		return "v4"
	}
	if strings.HasSuffix(name, "IPv6") {
		return "v6"
	}
	return name
}

func parseEndpoint(s string) (*net.UDPAddr, error) {
	// ensure that the host is an IP address

	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	if i := strings.LastIndexByte(host, '%'); i > 0 && strings.IndexByte(host, ':') >= 0 {
		// Remove the scope, if any. ResolveUDPAddr below will use it, but here we're just
		// trying to make sure with a small sanity test that this is a real IP address and
		// not something that's likely to incur DNS lookups.
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("Failed to parse IP address: " + host)
	}

	// parse address and port

	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		addr.IP = ip4
	}
	return addr, err
}
