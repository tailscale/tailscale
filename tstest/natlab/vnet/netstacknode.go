// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// InjectEthernetFrameForTest injects an ethernet frame into the virtual network
// as though the node owning the frame's source MAC had sent it.
//
// It is the counterpart to [Server.RegisterSinkForTest]: together they let a
// test attach to a network in-process, without a virtual machine. See
// [NetstackNode].
func (s *Server) InjectEthernetFrameForTest(frame []byte) error {
	return s.handleEthernetFrameFromVM(frame)
}

// nsNICID is the NIC ID used by every [NetstackNode]. Each node has its own
// stack, so they don't collide.
const nsNICID = tcpip.NICID(1)

// NetstackNode is a node on a virtual network that runs in this process,
// backed by gVisor netstack rather than a virtual machine.
//
// It exists so that Go code under test can be the client on a simulated
// network: connections it makes are real TCP over real ethernet frames, routed
// and NATed by vnet exactly as a VM's would be, and its DNS queries are real
// UDP to the network's DNS server. That makes it possible to test code against
// network conditions — a captive portal intercepting HTTP, a walled garden
// dropping everything, a hijacked resolver — without booting a VM.
//
// Unlike a VM, it takes its address statically from the config rather than over
// DHCP; there's no DHCP client here.
type NetstackNode struct {
	s   *Server
	mac MAC
	ip  netip.Addr   // this node's LAN address
	gw  netip.Addr   // the network's router
	dns netip.Addr   // the DNS server to query
	ns  *stack.Stack //

	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewNetstackNode brings up an in-process netstack node for the given
// configured node, which must be on an IPv4 network.
//
// The Server must already have been created by [New], since that's what
// assigns the node its address.
func (s *Server) NewNetstackNode(conf *Node) (*NetstackNode, error) {
	netw := conf.Network()
	if netw == nil {
		return nil, fmt.Errorf("node %v is not on any network", conf)
	}
	prefix := netw.LANIP4()
	if !prefix.IsValid() {
		return nil, fmt.Errorf("node %v is on a network with no IPv4 LAN", conf)
	}
	ip := conf.LanIP(netw)
	if !ip.IsValid() {
		return nil, fmt.Errorf("node %v has no IPv4 LAN address; was the Server created?", conf)
	}

	nn := &NetstackNode{
		s:   s,
		mac: conf.MAC(),
		ip:  ip,
		gw:  netw.GatewayIP4(),
		dns: FakeDNSIPv4(),
	}

	nn.ns = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol, // so the stack can resolve the router's MAC
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	// The ethernet wrapper is what makes this a LAN node rather than a
	// point-to-point link: it frames outbound packets and consumes the header
	// on inbound ones, and it's what tells the stack to do ARP.
	linkEP := channel.New(512, 1500, tcpip.LinkAddress(nn.mac[:]))
	if err := nn.ns.CreateNIC(nsNICID, ethernet.New(linkEP)); err != nil {
		return nil, fmt.Errorf("CreateNIC: %v", err)
	}
	if err := nn.ns.AddProtocolAddress(nsNICID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(ip.As4()),
			PrefixLen: prefix.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, err)
	}

	lanSubnet, tcpipErr := tcpip.NewSubnet(
		tcpip.AddrFrom4(prefix.Masked().Addr().As4()),
		tcpip.MaskFromBytes(net.CIDRMask(prefix.Bits(), 32)))
	if tcpipErr != nil {
		return nil, fmt.Errorf("NewSubnet(%v): %v", prefix, tcpipErr)
	}
	nn.ns.SetRouteTable([]tcpip.Route{
		{Destination: lanSubnet, NIC: nsNICID},
		{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4(nn.gw.As4()),
			NIC:         nsNICID,
		},
	})

	ctx, cancel := context.WithCancel(s.shutdownCtx)
	nn.cancel = cancel

	// Outbound: frames the stack writes go into the virtual network.
	s.wg.Go(func() {
		for {
			pkt := linkEP.ReadContext(ctx)
			if pkt == nil {
				return // context canceled
			}
			frame := pkt.ToView().AsSlice()
			if err := s.InjectEthernetFrameForTest(frame); err != nil {
				s.logf("NetstackNode %v: injecting frame: %v", nn.ip, err)
			}
			pkt.DecRef()
		}
	})

	// Inbound: frames the virtual network sends to our MAC go into the stack.
	s.RegisterSinkForTest(nn.mac, func(eth []byte) {
		if ctx.Err() != nil {
			return
		}
		// Clone: the caller reuses its buffer.
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(bytes.Clone(eth)),
		})
		linkEP.InjectInbound(0 /* derived from the ethernet header */, pkt)
		pkt.DecRef()
	})

	return nn, nil
}

// IP returns the node's LAN address.
func (nn *NetstackNode) IP() netip.Addr { return nn.ip }

// Close shuts the node down.
func (nn *NetstackNode) Close() error {
	nn.closeOnce.Do(func() {
		nn.cancel()
		nn.ns.Close()
	})
	return nil
}

// DialContext dials from inside the virtual network.
//
// It resolves hostnames through the network's DNS server, so a name pointed
// somewhere unexpected by a hijacking resolver leads where the resolver said,
// just as it would for a real client.
//
// It is suitable as an [http.Transport.DialContext].
func (nn *NetstackNode) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := nn.resolveOne(ctx, host)
	if err != nil {
		return nil, err
	}
	full := tcpip.FullAddress{
		NIC:  nsNICID,
		Addr: tcpip.AddrFrom4(ip.As4()),
		Port: port,
	}
	switch network {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, nn.ns, full, ipv4.ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(nn.ns, nil, &full, ipv4.ProtocolNumber)
	case "tcp6", "udp6":
		// This node is IPv4-only; report it the way a host with no IPv6
		// would, so callers fall back rather than hang.
		return nil, fmt.Errorf("dial %s: %w", network, errors.ErrUnsupported)
	}
	return nil, fmt.Errorf("unsupported network %q", network)
}

// Resolver returns a resolver that queries the virtual network's DNS server
// over the virtual network.
func (nn *NetstackNode) Resolver() *net.Resolver {
	return &net.Resolver{
		// Force Go's own resolver: cgo's would use the host's real
		// configuration and never touch the virtual network.
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Ignore the address Go picked from the host's resolv.conf and use
			// the network's own server, which is what DHCP would have told a
			// real client to use.
			return nn.DialContext(ctx, network, net.JoinHostPort(nn.dns.String(), "53"))
		},
	}
}

// LookupIP resolves a hostname to IPv4 addresses over the virtual network.
func (nn *NetstackNode) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return nn.Resolver().LookupNetIP(ctx, "ip4", host)
}

// resolveOne returns a single address for host, which may already be a literal
// IP address.
func (nn *NetstackNode) resolveOne(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("dial %v: %w", ip, errors.ErrUnsupported)
		}
		return ip, nil
	}
	addrs, err := nn.LookupIP(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %q", host)
	}
	return addrs[0].Unmap(), nil
}

func splitHostPort(addr string) (host string, port uint16, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	pn, err := net.LookupPort("tcp", p)
	if err != nil {
		return "", 0, err
	}
	return h, uint16(pn), nil
}
