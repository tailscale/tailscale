// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"fmt"
	"net"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

func parseIP(host string, defaultBits int) (filter.Net, error) {
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		// For clarity, reject 0.0.0.0 as an input
		return filter.NetNone, fmt.Errorf("ports=%#v: to allow all IP addresses, use *:port, not 0.0.0.0:port", host)
	} else if ip == nil && host == "*" {
		// User explicitly requested wildcard dst ip
		return filter.NetAny, nil
	} else {
		if ip != nil {
			ip = ip.To4()
		}
		if ip == nil || len(ip) != 4 {
			return filter.NetNone, fmt.Errorf("ports=%#v: invalid IPv4 address", host)
		}
		return filter.Net{
			IP:   filter.NewIP(ip),
			Mask: filter.Netmask(defaultBits),
		}, nil
	}
}

// Parse a backward-compatible FilterRule used by control's wire format,
// producing the most current filter.Matches format.
func (c *Direct) parsePacketFilter(pf []tailcfg.FilterRule) filter.Matches {
	mm := make([]filter.Match, 0, len(pf))
	var erracc error

	for _, r := range pf {
		m := filter.Match{}

		for i, s := range r.SrcIPs {
			bits := 32
			if len(r.SrcBits) > i {
				bits = r.SrcBits[i]
			}
			net, err := parseIP(s, bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Srcs = append(m.Srcs, net)
		}

		for _, d := range r.DstPorts {
			bits := 32
			if d.Bits != nil {
				bits = *d.Bits
			}
			net, err := parseIP(d.IP, bits)
			if err != nil && erracc == nil {
				erracc = err
				continue
			}
			m.Dsts = append(m.Dsts, filter.NetPortRange{
				Net: net,
				Ports: filter.PortRange{
					First: d.Ports.First,
					Last:  d.Ports.Last,
				},
			})
		}

		mm = append(mm, m)
	}

	if erracc != nil {
		c.logf("parsePacketFilter: %s\n", erracc)
	}
	return mm
}
