// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package natlab

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// mapping is the state of an allocated NAT session.
type mapping struct {
	lanSrc   netip.AddrPort
	lanDst   netip.AddrPort
	wanSrc   netip.AddrPort
	deadline time.Time

	// pc is a PacketConn that reserves an outbound port on the NAT's
	// WAN interface. We do this because ListenPacket already has
	// random port selection logic built in. Additionally this means
	// that concurrent use of ListenPacket for connections originating
	// from the NAT box won't conflict with NAT mappings, since both
	// use PacketConn to reserve ports on the machine.
	pc net.PacketConn
}

// NATType is the mapping behavior of a NAT device. Values express
// different modes defined by RFC 4787.
type NATType int

const (
	// EndpointIndependentNAT specifies a destination endpoint
	// independent NAT. All traffic from a source ip:port gets mapped
	// to a single WAN ip:port.
	EndpointIndependentNAT NATType = iota
	// AddressDependentNAT specifies a destination address dependent
	// NAT. Every distinct destination IP gets its own WAN ip:port
	// allocation.
	AddressDependentNAT
	// AddressAndPortDependentNAT specifies a destination
	// address-and-port dependent NAT. Every distinct destination
	// ip:port gets its own WAN ip:port allocation.
	AddressAndPortDependentNAT
)

// natKey is the lookup key for a NAT session. While it contains a
// 4-tuple ({src,dst} {ip,port}), some NATTypes will zero out some
// fields, so in practice the key is either a 2-tuple (src only),
// 3-tuple (src ip+port and dst ip) or 4-tuple (src+dst ip+port).
type natKey struct {
	src, dst netip.AddrPort
}

func (t NATType) key(src, dst netip.AddrPort) natKey {
	k := natKey{src: src}
	switch t {
	case EndpointIndependentNAT:
	case AddressDependentNAT:
		k.dst = netip.AddrPortFrom(dst.Addr(), k.dst.Port())
	case AddressAndPortDependentNAT:
		k.dst = dst
	default:
		panic(fmt.Sprintf("unknown NAT type %v", t))
	}
	return k
}

// DefaultMappingTimeout is the default timeout for a NAT mapping.
const DefaultMappingTimeout = 30 * time.Second

// SNAT44 implements an IPv4-to-IPv4 source NAT (SNAT) translator, with
// optional builtin firewall.
type SNAT44 struct {
	// Machine is the machine to which this NAT is attached. Altered
	// packets are injected back into this Machine for processing.
	Machine *Machine
	// ExternalInterface is the "WAN" interface of Machine. Packets
	// from other sources get NATed onto this interface.
	ExternalInterface *Interface
	// Type specifies the mapping allocation behavior for this NAT.
	Type NATType
	// MappingTimeout is the lifetime of individual NAT sessions. Once
	// a session expires, the mapped port effectively "closes" to new
	// traffic. If MappingTimeout is 0, DefaultMappingTimeout is used.
	MappingTimeout time.Duration
	// Firewall is an optional packet handler that will be invoked as
	// a firewall during NAT translation. The firewall always sees
	// packets in their "LAN form", i.e. before translation in the
	// outbound direction and after translation in the inbound
	// direction.
	Firewall PacketHandler
	// TimeNow is a function that returns the current time. If
	// nil, time.Now is used.
	TimeNow func() time.Time

	mu    sync.Mutex
	byLAN map[natKey]*mapping         // lookup by outbound packet tuple
	byWAN map[netip.AddrPort]*mapping // lookup by wan ip:port only
}

func (n *SNAT44) timeNow() time.Time {
	if n.TimeNow != nil {
		return n.TimeNow()
	}
	return time.Now()
}

func (n *SNAT44) mappingTimeout() time.Duration {
	if n.MappingTimeout == 0 {
		return DefaultMappingTimeout
	}
	return n.MappingTimeout
}

func (n *SNAT44) initLocked() {
	if n.byLAN == nil {
		n.byLAN = map[natKey]*mapping{}
		n.byWAN = map[netip.AddrPort]*mapping{}
	}
	if n.ExternalInterface.Machine() != n.Machine {
		panic(fmt.Sprintf("NAT given interface %s that is not part of given machine %s", n.ExternalInterface, n.Machine.Name))
	}
}

func (n *SNAT44) HandleOut(p *Packet, oif *Interface) *Packet {
	// NATs don't affect locally originated packets.
	if n.Firewall != nil {
		return n.Firewall.HandleOut(p, oif)
	}
	return p
}

func (n *SNAT44) HandleIn(p *Packet, iif *Interface) *Packet {
	if iif != n.ExternalInterface {
		// NAT can't apply, defer to firewall.
		if n.Firewall != nil {
			return n.Firewall.HandleIn(p, iif)
		}
		return p
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	n.initLocked()

	now := n.timeNow()
	mapping := n.byWAN[p.Dst]
	if mapping == nil || now.After(mapping.deadline) {
		// NAT didn't hit, defer to firewall or allow in for local
		// socket handling.
		if n.Firewall != nil {
			return n.Firewall.HandleIn(p, iif)
		}
		return p
	}

	p.Dst = mapping.lanSrc
	p.Trace("dnat to %v", p.Dst)
	// Don't process firewall here. We mutated the packet such that
	// it's no longer destined locally, so we'll get reinvoked as
	// HandleForward and need to process the altered packet there.
	return p
}

func (n *SNAT44) HandleForward(p *Packet, iif, oif *Interface) *Packet {
	switch {
	case oif == n.ExternalInterface:
		if p.Src.Addr() == oif.V4() {
			// Packet already NATed and is just retraversing Forward,
			// don't touch it again.
			return p
		}

		if n.Firewall != nil {
			p2 := n.Firewall.HandleForward(p, iif, oif)
			if p2 == nil {
				// firewall dropped, done
				return nil
			}
			if !p.Equivalent(p2) {
				// firewall mutated packet? Weird, but okay.
				return p2
			}
		}

		n.mu.Lock()
		defer n.mu.Unlock()
		n.initLocked()

		k := n.Type.key(p.Src, p.Dst)
		now := n.timeNow()
		m := n.byLAN[k]
		if m == nil || now.After(m.deadline) {
			pc, wanAddr := n.allocateMappedPort()
			m = &mapping{
				lanSrc: p.Src,
				lanDst: p.Dst,
				wanSrc: wanAddr,
				pc:     pc,
			}
			n.byLAN[k] = m
			n.byWAN[wanAddr] = m
		}
		m.deadline = now.Add(n.mappingTimeout())
		p.Src = m.wanSrc
		p.Trace("snat from %v", p.Src)
		return p
	case iif == n.ExternalInterface:
		// Packet was already un-NAT-ed, we just need to either
		// firewall it or let it through.
		if n.Firewall != nil {
			return n.Firewall.HandleForward(p, iif, oif)
		}
		return p
	default:
		// No NAT applies, invoke firewall or drop.
		if n.Firewall != nil {
			return n.Firewall.HandleForward(p, iif, oif)
		}
		return nil
	}
}

func (n *SNAT44) allocateMappedPort() (net.PacketConn, netip.AddrPort) {
	// Clean up old entries before trying to allocate, to free up any
	// expired ports.
	n.gc()

	ip := n.ExternalInterface.V4()
	pc, err := n.Machine.ListenPacket(context.Background(), "udp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		panic(fmt.Sprintf("ran out of NAT ports: %v", err))
	}
	addr := netip.AddrPortFrom(ip, uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	return pc, addr
}

func (n *SNAT44) gc() {
	now := n.timeNow()
	for _, m := range n.byLAN {
		if !now.After(m.deadline) {
			continue
		}
		m.pc.Close()
		delete(n.byLAN, n.Type.key(m.lanSrc, m.lanDst))
		delete(n.byWAN, m.wanSrc)
	}
}
