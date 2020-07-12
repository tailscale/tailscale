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

// EndpointDependence expresses
type FirewallSelectivity int

const (
	// APDF specifies a destination address-and-port dependent
	// firewall. Outbound traffic to an ip:port authorizes traffic
	// from that ip:port exactly, and nothing else.
	APDF FirewallSelectivity = iota
	// ADF specifies a destination address dependent firewall. Once
	// outbound traffic has been seen to an IP address, that IP
	// address can talk back from any port.
	ADF
	// EIF specifies a destination endpoint independent firewall. Once
	// outbound traffic has been seen from a source, anyone can talk
	// back to that source.
	EIF
)

type fwKey struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

func (s FirewallSelectivity) key(src, dst netaddr.IPPort) fwKey {
	k := fwKey{src: src}
	switch s {
	case EIF:
	case ADF:
		k.dst.IP = dst.IP
	case APDF:
		k.dst = dst
	default:
		panic(fmt.Sprintf("unknown firewall selectivity %v", s))
	}
	return k
}

// Firewall is a simple stateful firewall that allows all outbound
// traffic and filters inbound traffic based on recently seen outbound
// traffic. Its HandlePacket method should be attached to a Machine to
// give it a stateful firewall.
type Firewall struct {
	// SessionTimeout is the lifetime of idle sessions in the firewall
	// state. Packets transiting from the TrustedInterface reset the
	// session lifetime to SessionTimeout.
	SessionTimeout time.Duration
	// Selectivity specifies how precisely return traffic must match
	// previously seen outbound traffic to be allowed.
	Selectivity FirewallSelectivity
	// TrustedInterface is an optional interface that is considered
	// trusted in addition to the local host. All other interfaces can
	// only respond to traffic from TrustedInterface or the local
	// host.
	TrustedInterface *Interface
	// TimeNow is a function returning the current time. If nil,
	// time.Now is used.
	TimeNow func() time.Time

	// TODO: tuple-ness pickiness: EIF, ADF, APDF
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
		k := f.Selectivity.key(p.Src, p.Dst)
		f.seen[k] = f.timeNow().Add(f.SessionTimeout)
		p.Trace("firewall out ok")
		return Continue
	} else {
		// reverse src and dst because the session table is from the
		// POV of outbound packets.
		k := f.Selectivity.key(p.Dst, p.Src)
		now := f.timeNow()
		if now.After(f.seen[k]) {
			p.Trace("firewall drop")
			return Drop
		}
		p.Trace("firewall in ok")
		return Continue
	}
}
