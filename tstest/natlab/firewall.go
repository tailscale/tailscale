// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package natlab

import (
	"fmt"
	"sync"
	"time"

	"inet.af/netaddr"
)

// FirewallType is the type of filtering a stateful firewall
// does. Values express different modes defined by RFC 4787.
type FirewallType int

const (
	// AddressAndPortDependentFirewall specifies a destination
	// address-and-port dependent firewall. Outbound traffic to an
	// ip:port authorizes traffic from that ip:port exactly, and
	// nothing else.
	AddressAndPortDependentFirewall FirewallType = iota
	// AddressDependentFirewall specifies a destination address
	// dependent firewall. Once outbound traffic has been seen to an
	// IP address, that IP address can talk back from any port.
	AddressDependentFirewall
	// EndpointIndependentFirewall specifies a destination endpoint
	// independent firewall. Once outbound traffic has been seen from
	// a source, anyone can talk back to that source.
	EndpointIndependentFirewall
)

// fwKey is the lookup key for a firewall session. While it contains a
// 4-tuple ({src,dst} {ip,port}), some FirewallTypes will zero out
// some fields, so in practice the key is either a 2-tuple (src only),
// 3-tuple (src ip+port and dst ip) or 4-tuple (src+dst ip+port).
type fwKey struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

// key returns an fwKey for the given src and dst, trimmed according
// to the FirewallType. fwKeys are always constructed from the
// "outbound" point of view (i.e. src is the "trusted" side of the
// world), it's the caller's responsibility to swap src and dst in the
// call to key when processing packets inbound from the "untrusted"
// world.
func (s FirewallType) key(src, dst netaddr.IPPort) fwKey {
	k := fwKey{src: src}
	switch s {
	case EndpointIndependentFirewall:
	case AddressDependentFirewall:
		k.dst.IP = dst.IP
	case AddressAndPortDependentFirewall:
		k.dst = dst
	default:
		panic(fmt.Sprintf("unknown firewall selectivity %v", s))
	}
	return k
}

// DefaultSessionTimeout is the default timeout for a firewall
// session.
const DefaultSessionTimeout = 30 * time.Second

// Firewall is a simple stateful firewall that allows all outbound
// traffic and filters inbound traffic based on recently seen outbound
// traffic. Its HandlePacket method should be attached to a Machine to
// give it a stateful firewall.
type Firewall struct {
	// SessionTimeout is the lifetime of idle sessions in the firewall
	// state. Packets transiting from the TrustedInterface reset the
	// session lifetime to SessionTimeout. If zero,
	// DefaultSessionTimeout is used.
	SessionTimeout time.Duration
	// Type specifies how precisely return traffic must match
	// previously seen outbound traffic to be allowed. Defaults to
	// AddressAndPortDependentFirewall.
	Type FirewallType
	// TrustedInterface is an optional interface that is considered
	// trusted in addition to PacketConns local to the Machine. All
	// other interfaces can only respond to traffic from
	// TrustedInterface or the local host.
	TrustedInterface *Interface
	// TimeNow is a function returning the current time. If nil,
	// time.Now is used.
	TimeNow func() time.Time

	// TODO: refresh directionality: outbound-only, both

	mu   sync.Mutex
	seen map[fwKey]time.Time // session -> deadline
}

func (f *Firewall) timeNow() time.Time {
	if f.TimeNow != nil {
		return f.TimeNow()
	}
	return time.Now()
}

// HandlePacket implements the PacketHandler type.
func (f *Firewall) HandlePacket(p *Packet, inIf *Interface) PacketVerdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = map[fwKey]time.Time{}
	}
	if f.SessionTimeout == 0 {
		f.SessionTimeout = 30 * time.Second
	}

	if inIf == f.TrustedInterface || inIf == nil {
		k := f.Type.key(p.Src, p.Dst)
		f.seen[k] = f.timeNow().Add(f.SessionTimeout)
		p.Trace("firewall out ok")
		return Continue
	} else {
		// reverse src and dst because the session table is from the
		// POV of outbound packets.
		k := f.Type.key(p.Dst, p.Src)
		now := f.timeNow()
		if now.After(f.seen[k]) {
			p.Trace("firewall drop")
			return Drop
		}
		p.Trace("firewall in ok")
		return Continue
	}
}
