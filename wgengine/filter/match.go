// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/net/packet"
)

// PortRange is a range of TCP and UDP ports.
type PortRange struct {
	First, Last uint16 // inclusive
}

func (pr PortRange) String() string {
	if pr.First == 0 && pr.Last == 65535 {
		return "*"
	} else if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

// contains returns whether port is in pr.
func (pr PortRange) contains(port uint16) bool {
	return port >= pr.First && port <= pr.Last
}

// NetPortRange combines an IP address prefix and PortRange.
type NetPortRange struct {
	Net   netaddr.IPPrefix
	Ports PortRange
}

func (npr NetPortRange) String() string {
	return fmt.Sprintf("%v:%v", npr.Net, npr.Ports)
}

// Match matches packets from any IP address in Srcs to any ip:port in
// Dsts.
type Match struct {
	Dsts []NetPortRange
	Srcs []netaddr.IPPrefix
}

func (m Match) String() string {
	srcs := []string{}
	for _, src := range m.Srcs {
		srcs = append(srcs, src.String())
	}
	dsts := []string{}
	for _, dst := range m.Dsts {
		dsts = append(dsts, dst.String())
	}

	var ss, ds string
	if len(srcs) == 1 {
		ss = srcs[0]
	} else {
		ss = "[" + strings.Join(srcs, ",") + "]"
	}
	if len(dsts) == 1 {
		ds = dsts[0]
	} else {
		ds = "[" + strings.Join(dsts, ",") + "]"
	}
	return fmt.Sprintf("%v=>%v", ss, ds)
}

type matches []Match

func (ms matches) match(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ipInList(q.Src.IP, m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if !dst.Net.Contains(q.Dst.IP) {
				continue
			}
			if !dst.Ports.contains(q.Dst.Port) {
				continue
			}
			return true
		}
	}
	return false
}

func (ms matches) matchIPsOnly(q *packet.Parsed) bool {
	for _, m := range ms {
		if !ipInList(q.Src.IP, m.Srcs) {
			continue
		}
		for _, dst := range m.Dsts {
			if dst.Net.Contains(q.Dst.IP) {
				return true
			}
		}
	}
	return false
}

func ipInList(ip netaddr.IP, netlist []netaddr.IPPrefix) bool {
	for _, net := range netlist {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
