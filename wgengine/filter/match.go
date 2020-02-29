// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"fmt"
	"strings"

	"tailscale.com/wgengine/packet"
)

type IP = packet.IP

const IPAny = IP(0)

var NewIP = packet.NewIP

type PortRange struct {
	First, Last uint16
}

var PortRangeAny = PortRange{0, 65535}

func (pr PortRange) String() string {
	if pr.First == 0 && pr.Last == 65535 {
		return "*"
	} else if pr.First == pr.Last {
		return fmt.Sprintf("%d", pr.First)
	} else {
		return fmt.Sprintf("%d-%d", pr.First, pr.Last)
	}
}

type IPPortRange struct {
	IP    IP
	Ports PortRange
}

var IPPortRangeAny = IPPortRange{IPAny, PortRangeAny}

func (ipr IPPortRange) String() string {
	return fmt.Sprintf("%v:%v", ipr.IP, ipr.Ports)
}

type Match struct {
	DstPorts []IPPortRange
	SrcIPs   []IP
}

func (m Match) Clone() (res Match) {
	if m.DstPorts != nil {
		res.DstPorts = append([]IPPortRange{}, m.DstPorts...)
	}
	if m.SrcIPs != nil {
		res.SrcIPs = append([]IP{}, m.SrcIPs...)
	}
	return res
}

func (m Match) String() string {
	srcs := []string{}
	for _, srcip := range m.SrcIPs {
		srcs = append(srcs, srcip.String())
	}
	dsts := []string{}
	for _, dst := range m.DstPorts {
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

type Matches []Match

func (m Matches) Clone() (res Matches) {
	for _, match := range m {
		res = append(res, match.Clone())
	}
	return res
}

func ipInList(ip IP, iplist []IP) bool {
	for _, ipp := range iplist {
		if ipp == IPAny || ipp == ip {
			return true
		}
	}
	return false
}

func matchIPPorts(mm Matches, q *packet.QDecode) bool {
	for _, acl := range mm {
		for _, dst := range acl.DstPorts {
			if dst.IP != IPAny && dst.IP != q.DstIP {
				continue
			}
			if q.DstPort < dst.Ports.First || q.DstPort > dst.Ports.Last {
				continue
			}
			if !ipInList(q.SrcIP, acl.SrcIPs) {
				// Skip other dests in this acl, since
				// the src will never match.
				break
			}
			return true
		}
	}
	return false
}

func matchIPWithoutPorts(mm Matches, q *packet.QDecode) bool {
	for _, acl := range mm {
		for _, dst := range acl.DstPorts {
			if dst.IP != IPAny && dst.IP != q.DstIP {
				continue
			}
			if !ipInList(q.SrcIP, acl.SrcIPs) {
				// Skip other dests in this acl, since
				// the src will never match.
				break
			}
			return true
		}
	}
	return false
}
