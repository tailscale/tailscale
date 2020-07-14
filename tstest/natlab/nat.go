// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package natlab

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"inet.af/netaddr"
)

// mapping is the state of an allocated NAT session.
type mapping struct {
	lanSrc   netaddr.IPPort
	lanDst   netaddr.IPPort
	wanSrc   netaddr.IPPort
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
	src, dst netaddr.IPPort
}

func (t NATType) key(src, dst netaddr.IPPort) natKey {
	k := natKey{src: src}
	switch t {
	case EndpointIndependentNAT:
	case AddressDependentNAT:
		k.dst.IP = dst.IP
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

	// inject, if not nil, will be invoked instead of Machine.Inject
	// to inject NATed packets into the network. It is used for tests
	// only.
	inject func(*Packet) error

	mu    sync.Mutex
	byLAN map[natKey]*mapping         // lookup by outbound packet tuple
	byWAN map[netaddr.IPPort]*mapping // lookup by wan ip:port only
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
		n.byWAN = map[netaddr.IPPort]*mapping{}
	}
	if n.ExternalInterface.Machine() != n.Machine {
		panic(fmt.Sprintf("NAT given interface %s that is not part of given machine %s", n.ExternalInterface, n.Machine.Name))
	}
	if n.inject == nil {
		n.inject = n.Machine.Inject
	}
}

func (n *SNAT44) HandlePacket(p *Packet, inIf *Interface) PacketVerdict {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.initLocked()

	if inIf == n.ExternalInterface {
		return n.processInboundLocked(p, inIf)
	} else {
		return n.processOutboundLocked(p, inIf)
	}
}

func (n *SNAT44) processInboundLocked(p *Packet, inIf *Interface) PacketVerdict {
	// TODO: packets to local addrs should fall through to local
	// socket processing.
	now := n.timeNow()
	mapping := n.byWAN[p.Dst]
	if mapping == nil || now.After(mapping.deadline) {
		p.Trace("nat drop, no mapping/expired mapping")
		return Drop
	}
	p.Dst = mapping.lanSrc

	if n.Firewall != nil {
		if verdict := n.Firewall(p.Clone(), inIf); verdict == Drop {
			return Drop
		}
	}

	if err := n.inject(p); err != nil {
		p.Trace("inject failed: %v", err)
	}
	return Drop
}

func (n *SNAT44) processOutboundLocked(p *Packet, inIf *Interface) PacketVerdict {
	if n.Firewall != nil {
		if verdict := n.Firewall(p, inIf); verdict == Drop {
			return Drop
		}
	}
	if inIf == nil {
		// Technically, we don't need to process the outbound firewall
		// for NATed packets, but our current packet processing API
		// doesn't give us that granularity: we'll see both locally
		// originated PacketConn traffic and NATed traffic as inIf ==
		// nil, and we need to apply the firewall to locally
		// originated traffic. This may create some useless state
		// entries in the firewall, but until we implement a much more
		// elaborate packet processing pipeline that can distinguish
		// local vs. forwarded traffic, this is the best we have.
		return Continue
	}

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
	if err := n.inject(p); err != nil {
		p.Trace("inject failed: %v", err)
	}
	return Drop
}

func (n *SNAT44) allocateMappedPort() (net.PacketConn, netaddr.IPPort) {
	// Clean up old entries before trying to allocate, to free up any
	// expired ports.
	n.gc()

	ip := n.ExternalInterface.V4()
	pc, err := n.Machine.ListenPacket(context.Background(), "udp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		panic(fmt.Sprintf("ran out of NAT ports: %v", err))
	}
	addr := netaddr.IPPort{
		IP:   ip,
		Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port),
	}
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
