// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"inet.af/netaddr"
	"inet.af/netstack/tcpip"
	"inet.af/netstack/tcpip/adapters/gonet"
	"inet.af/netstack/tcpip/buffer"
	"inet.af/netstack/tcpip/header"
	"inet.af/netstack/tcpip/link/channel"
	"inet.af/netstack/tcpip/network/ipv4"
	"inet.af/netstack/tcpip/network/ipv6"
	"inet.af/netstack/tcpip/stack"
	"inet.af/netstack/tcpip/transport/icmp"
	"inet.af/netstack/tcpip/transport/tcp"
	"inet.af/netstack/tcpip/transport/udp"
	"inet.af/netstack/waiter"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/tstun"
)

const debugNetstack = false

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	ipstack *stack.Stack
	linkEP  *channel.Endpoint
	tundev  *tstun.TUN
	e       wgengine.Engine
	mc      *magicsock.Conn
	logf    logger.Logf

	mu  sync.Mutex
	dns DNSMap
}

const nicID = 1
const mtu = 1500

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.TUN, e wgengine.Engine, mc *magicsock.Conn) (*Impl, error) {
	if mc == nil {
		return nil, errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return nil, errors.New("nil tundev")
	}
	if logf == nil {
		return nil, errors.New("nil logger")
	}
	if e == nil {
		return nil, errors.New("nil Engine")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	linkEP := channel.New(512, mtu, "")
	if tcpipProblem := ipstack.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", tcpipProblem)
	}
	// Add IPv4 and IPv6 default routes, so all incoming packets from the Tailscale side
	// are handled by the one fake NIC we use.
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})
	ns := &Impl{
		logf:    logf,
		ipstack: ipstack,
		linkEP:  linkEP,
		tundev:  tundev,
		e:       e,
		mc:      mc,
	}
	return ns, nil
}

// Start sets up all the handlers so netstack can start working. Implements
// wgengine.FakeImpl.
func (ns *Impl) Start() error {
	ns.e.AddNetworkMapCallback(ns.updateIPs)
	// size = 0 means use default buffer size
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 16
	tcpFwd := tcp.NewForwarder(ns.ipstack, tcpReceiveBufferSize, maxInFlightConnectionAttempts, ns.acceptTCP)
	udpFwd := udp.NewForwarder(ns.ipstack, ns.acceptUDP)
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	go ns.injectOutbound()
	ns.tundev.PostFilterIn = ns.injectInbound
	return nil
}

// DNSMap maps MagicDNS names (both base + FQDN) to their first IP.
// It should not be mutated once created.
type DNSMap map[string]netaddr.IP

func DNSMapFromNetworkMap(nm *netmap.NetworkMap) DNSMap {
	ret := make(DNSMap)
	suffix := nm.MagicDNSSuffix()

	if nm.Name != "" && len(nm.Addresses) > 0 {
		ip := nm.Addresses[0].IP
		ret[strings.TrimRight(nm.Name, ".")] = ip
		if dnsname.HasSuffix(nm.Name, suffix) {
			ret[dnsname.TrimSuffix(nm.Name, suffix)] = ip
		}
	}
	for _, p := range nm.Peers {
		if p.Name != "" && len(p.Addresses) > 0 {
			ip := p.Addresses[0].IP
			ret[strings.TrimRight(p.Name, ".")] = ip
			if dnsname.HasSuffix(p.Name, suffix) {
				ret[dnsname.TrimSuffix(p.Name, suffix)] = ip
			}
		}
	}
	return ret
}

func (ns *Impl) updateDNS(nm *netmap.NetworkMap) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.dns = DNSMapFromNetworkMap(nm)
}

func (ns *Impl) updateIPs(nm *netmap.NetworkMap) {
	ns.updateDNS(nm)

	oldIPs := make(map[tcpip.Address]bool)
	for _, ip := range ns.ipstack.AllAddresses()[nicID] {
		oldIPs[ip.AddressWithPrefix.Address] = true
	}
	newIPs := make(map[tcpip.Address]bool)
	for _, ip := range nm.Addresses {
		newIPs[tcpip.Address(ip.IP.IPAddr().IP)] = true
	}

	ipsToBeAdded := make(map[tcpip.Address]bool)
	for ip := range newIPs {
		if !oldIPs[ip] {
			ipsToBeAdded[ip] = true
		}
	}
	ipsToBeRemoved := make(map[tcpip.Address]bool)
	for ip := range oldIPs {
		if !newIPs[ip] {
			ipsToBeRemoved[ip] = true
		}
	}

	for ip := range ipsToBeRemoved {
		err := ns.ipstack.RemoveAddress(nicID, ip)
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", ip, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", ip)
		}
	}
	for ip := range ipsToBeAdded {
		var err tcpip.Error
		if ip.To4() == "" {
			err = ns.ipstack.AddAddress(nicID, ipv6.ProtocolNumber, ip)
		} else {
			err = ns.ipstack.AddAddress(nicID, ipv4.ProtocolNumber, ip)
		}
		if err != nil {
			ns.logf("netstack: could not register IP %s: %v", ip, err)
		} else {
			ns.logf("[v2] netstack: registered IP %s", ip)
		}
	}
}

// Resolve resolves addr into an IP:port using first the MagicDNS contents
// of m, else using the system resolver.
func (m DNSMap) Resolve(ctx context.Context, addr string) (netaddr.IPPort, error) {
	ipp, pippErr := netaddr.ParseIPPort(addr)
	if pippErr == nil {
		return ipp, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr is malformed.
		return netaddr.IPPort{}, err
	}
	if net.ParseIP(host) != nil {
		// The host part of addr was an IP, so the netaddr.ParseIPPort above should've
		// passed. Must've been a bad port number. Return the original error.
		return netaddr.IPPort{}, pippErr
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netaddr.IPPort{}, fmt.Errorf("invalid port in address %q", addr)
	}

	// Host is not an IP, so assume it's a DNS name.

	// Try MagicDNS first, else otherwise a real DNS lookup.
	ip := m[host]
	if !ip.IsZero() {
		return netaddr.IPPort{IP: ip, Port: uint16(port16)}, nil
	}

	// No Magic DNS name so try real DNS.
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip", host)
	if err != nil {
		return netaddr.IPPort{}, err
	}
	if len(ips) == 0 {
		return netaddr.IPPort{}, fmt.Errorf("DNS lookup returned no results for %q", host)
	}
	ip, _ = netaddr.FromStdIP(ips[0])
	return netaddr.IPPort{IP: ip, Port: uint16(port16)}, nil
}

func (ns *Impl) DialContextTCP(ctx context.Context, addr string) (*gonet.TCPConn, error) {
	ns.mu.Lock()
	dnsMap := ns.dns
	ns.mu.Unlock()

	remoteIPPort, err := dnsMap.Resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(remoteIPPort.IP.IPAddr().IP),
		Port: remoteIPPort.Port,
	}
	var ipType tcpip.NetworkProtocolNumber
	if remoteIPPort.IP.Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialContextTCP(ctx, ns.ipstack, remoteAddress, ipType)
}

func (ns *Impl) injectOutbound() {
	for {
		packetInfo, ok := ns.linkEP.ReadContext(context.Background())
		if !ok {
			ns.logf("[v2] ReadContext-for-write = ok=false")
			continue
		}
		pkt := packetInfo.Pkt
		hdrNetwork := pkt.NetworkHeader()
		hdrTransport := pkt.TransportHeader()

		full := make([]byte, 0, pkt.Size())
		full = append(full, hdrNetwork.View()...)
		full = append(full, hdrTransport.View()...)
		full = append(full, pkt.Data().AsRange().AsView()...)
		if debugNetstack {
			ns.logf("[v2] packet Write out: % x", full)
		}
		if err := ns.tundev.InjectOutbound(full); err != nil {
			log.Printf("netstack inject outbound: %v", err)
			return
		}

	}
}

func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.TUN) filter.Response {
	var pn tcpip.NetworkProtocolNumber
	switch p.IPVersion {
	case 4:
		pn = header.IPv4ProtocolNumber
	case 6:
		pn = header.IPv6ProtocolNumber
	}
	if debugNetstack {
		ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	}
	vv := buffer.View(append([]byte(nil), p.Buffer()...)).ToVectorisedView()
	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: vv,
	})
	ns.linkEP.InjectInbound(pn, packetBuf)
	return filter.Accept
}

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	if debugNetstack {
		// Kinda ugly:
		// ForwarderRequest: &{{{{0 0}}} 0xc0001c30b0 0xc0004c3d40 {1240 6 true 826109390 0 true}
		ns.logf("[v2] ForwarderRequest: %v", r)
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	localAddr, err := ep.GetLocalAddress()
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	go ns.forwardTCP(c, &wq, localAddr.Port)
}

func (ns *Impl) forwardTCP(client *gonet.TCPConn, wq *waiter.Queue, port uint16) {
	defer client.Close()
	ns.logf("[v2] netstack: forwarding incoming connection on port %v", port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventHUp)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
		case <-done:
		}
		cancel()
	}()
	var stdDialer net.Dialer
	server, err := stdDialer.DialContext(ctx, "tcp", net.JoinHostPort("localhost", strconv.Itoa(int(port))))
	if err != nil {
		ns.logf("netstack: could not connect to local server on port %v: %v", port, err)
		return
	}
	defer server.Close()
	backendLocalAddr := server.LocalAddr().(*net.TCPAddr)
	backendLocalIPPort, _ := netaddr.FromStdAddr(backendLocalAddr.IP, backendLocalAddr.Port, backendLocalAddr.Zone)
	clientRemoteIP, _ := netaddr.FromStdIP(client.RemoteAddr().(*net.TCPAddr).IP)
	ns.e.RegisterIPPortIdentity(backendLocalIPPort, clientRemoteIP)
	defer ns.e.UnregisterIPPortIdentity(backendLocalIPPort)
	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, client)
		connClosed <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		connClosed <- err
	}()
	err = <-connClosed
	if err != nil {
		ns.logf("proxy connection closed with error: %v", err)
	}
	ns.logf("[v2] netstack: forwarder connection on port %v closed", port)
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	ns.logf("[v2] UDP ForwarderRequest: %v", r)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("Could not create endpoint, exiting")
		return
	}
	localAddr, err := ep.GetLocalAddress()
	if err != nil {
		return
	}
	remoteAddr, err := ep.GetRemoteAddress()
	if err != nil {
		return
	}
	c := gonet.NewUDPConn(ns.ipstack, &wq, ep)
	go ns.forwardUDP(c, &wq, localAddr, remoteAddr)
}

func (ns *Impl) forwardUDP(client *gonet.UDPConn, wq *waiter.Queue, clientLocalAddr, clientRemoteAddr tcpip.FullAddress) {
	port := clientLocalAddr.Port
	ns.logf("[v2] netstack: forwarding incoming UDP connection on port %v", port)
	backendListenAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(clientRemoteAddr.Port)}
	backendRemoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
	backendConn, err := net.ListenUDP("udp4", backendListenAddr)
	if err != nil {
		ns.logf("netstack: could not bind local port %v: %v, trying again with random port", clientRemoteAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp4", backendListenAddr)
		if err != nil {
			ns.logf("netstack: could not connect to local UDP server on port %v: %v", port, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)
	backendLocalIPPort, ok := netaddr.FromStdAddr(backendListenAddr.IP, backendLocalAddr.Port, backendLocalAddr.Zone)
	if !ok {
		ns.logf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	clientRemoteIP, _ := netaddr.FromStdIP(net.ParseIP(clientRemoteAddr.Addr.String()))
	ns.e.RegisterIPPortIdentity(backendLocalIPPort, clientRemoteIP)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(2*time.Minute, func() {
		ns.e.UnregisterIPPortIdentity(backendLocalIPPort)
		ns.logf("netstack: UDP session between %s and %s timed out", clientRemoteAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(2 * time.Minute)
	}
	startPacketCopy(ctx, cancel, client, &net.UDPAddr{
		IP:   net.ParseIP(clientRemoteAddr.Addr.String()),
		Port: int(clientRemoteAddr.Port),
	}, backendConn, ns.logf, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, ns.logf, extend)

}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, logf logger.Logf, extend func()) {
	go func() {
		defer cancel() // tear down the other direction's copy
		pkt := make([]byte, mtu)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						logf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						logf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				if debugNetstack {
					logf("[v2] wrote UDP packet %s -> %s", srcAddr, dstAddr)
				}
				extend()
			}
		}
	}()
}
