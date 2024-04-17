// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package routetable provides functions that operate on the system's route
// table.
package routetable

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"

	"tailscale.com/types/logger"
)

var (
	//lint:ignore U1000 used in routetable_linux_test.go and routetable_bsd_test.go
	defaultRouteIPv4 = RouteDestination{Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	//lint:ignore U1000 used in routetable_bsd_test.go
	defaultRouteIPv6 = RouteDestination{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
)

// RouteEntry contains common cross-platform fields describing an entry in the
// system route table.
type RouteEntry struct {
	// Family is the IP family of the route; it will be either 4 or 6.
	Family int
	// Type is the type of this route.
	Type RouteType
	// Dst is the destination of the route.
	Dst RouteDestination
	// Gatewayis the gateway address specified for this route.
	// This value will be invalid (where !r.Gateway.IsValid()) in cases
	// where there is no gateway address for this route.
	Gateway netip.Addr
	// Interface is the name of the network interface to use when sending
	// packets that match this route. This field can be empty.
	Interface string
	// Sys contains platform-specific information about this route.
	Sys any
}

// Format implements the fmt.Formatter interface.
func (r RouteEntry) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		switch r.Family {
		case 4:
			fmt.Fprintf(w, "{Family: IPv4")
		case 6:
			fmt.Fprintf(w, "{Family: IPv6")
		default:
			fmt.Fprintf(w, "{Family: unknown(%d)", r.Family)
		}

		// Match 'ip route' and other tools by not printing the route
		// type if it's a unicast route.
		if r.Type != RouteTypeUnicast {
			fmt.Fprintf(w, ", Type: %s", r.Type)
		}

		if r.Dst.IsValid() {
			fmt.Fprintf(w, ", Dst: %s", r.Dst)
		} else {
			w.WriteString(", Dst: invalid")
		}

		if r.Gateway.IsValid() {
			fmt.Fprintf(w, ", Gateway: %s", r.Gateway)
		}

		if r.Interface != "" {
			fmt.Fprintf(w, ", Interface: %s", r.Interface)
		}

		if r.Sys != nil {
			var formatVerb string
			switch {
			case f.Flag('#'):
				formatVerb = "%#v"
			case f.Flag('+'):
				formatVerb = "%+v"
			default:
				formatVerb = "%v"
			}
			fmt.Fprintf(w, ", Sys: "+formatVerb, r.Sys)
		}

		w.WriteString("}")
	}).Format(f, verb)
}

// RouteDestination is the destination of a route.
//
// This is similar to net/netip.Prefix, but also contains an optional IPv6
// zone.
type RouteDestination struct {
	netip.Prefix
	Zone string
}

func (r RouteDestination) String() string {
	ip := r.Prefix.Addr()
	if r.Zone != "" {
		ip = ip.WithZone(r.Zone)
	}
	return ip.String() + "/" + strconv.Itoa(r.Prefix.Bits())
}

// RouteType describes the type of a route.
type RouteType int

const (
	// RouteTypeUnspecified is the unspecified route type.
	RouteTypeUnspecified RouteType = iota
	// RouteTypeLocal indicates that the destination of this route is an
	// address that belongs to this system.
	RouteTypeLocal
	// RouteTypeUnicast indicates that the destination of this route is a
	// "regular" address--one that neither belongs to this host, nor is a
	// broadcast/multicast/etc. address.
	RouteTypeUnicast
	// RouteTypeBroadcast indicates that the destination of this route is a
	// broadcast address.
	RouteTypeBroadcast
	// RouteTypeMulticast indicates that the destination of this route is a
	// multicast address.
	RouteTypeMulticast
	// RouteTypeOther indicates that the route is of some other valid type;
	// see the Sys field for the OS-provided route information to determine
	// the exact type.
	RouteTypeOther
)

func (r RouteType) String() string {
	switch r {
	case RouteTypeUnspecified:
		return "unspecified"
	case RouteTypeLocal:
		return "local"
	case RouteTypeUnicast:
		return "unicast"
	case RouteTypeBroadcast:
		return "broadcast"
	case RouteTypeMulticast:
		return "multicast"
	case RouteTypeOther:
		return "other"
	default:
		return "invalid"
	}
}
