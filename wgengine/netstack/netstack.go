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
	"sync/atomic"
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
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

const debugNetstack = false

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	ipstack     *stack.Stack
	linkEP      *channel.Endpoint
	tundev      *tstun.Wrapper
	e           wgengine.Engine
	mc          *magicsock.Conn
	logf        logger.Logf
	onlySubnets bool // whether we only want to handle subnet relaying

	// atomicIsLocalIPFunc holds a func that reports whether an IP
	// is a local (non-subnet) Tailscale IP address of this
	// machine. It's always a non-nil func. It's changed on netmap
	// updates.
	atomicIsLocalIPFunc atomic.Value // of func(netaddr.IP) bool

	mu  sync.Mutex
	dns DNSMap
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netaddr.IP]int
}

const nicID = 1
const mtu = 1500

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.Wrapper, e wgengine.Engine, mc *magicsock.Conn, onlySubnets bool) (*Impl, error) {
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
	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since Wireguard will only send us packets that are meant for us.
	ipstack.SetPromiscuousMode(nicID, true)
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
		logf:                logf,
		ipstack:             ipstack,
		linkEP:              linkEP,
		tundev:              tundev,
		e:                   e,
		mc:                  mc,
		connsOpenBySubnetIP: make(map[netaddr.IP]int),
		onlySubnets:         onlySubnets,
	}
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nil))
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
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		addr := tei.LocalAddress
		var pn tcpip.NetworkProtocolNumber
		if addr.To4() != "" {
			pn = ipv4.ProtocolNumber
		} else {
			pn = ipv6.ProtocolNumber
		}
		ip, ok := netaddr.FromStdIP(net.IP(addr))
		if !ok {
			ns.logf("netstack: could not parse local address %s for incoming TCP connection", ip)
			return false
		}
		if !ns.isLocalIP(ip) {
			ns.addSubnetAddress(pn, ip)
		}
		return tcpFwd.HandlePacket(tei, pb)
	})
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

func (ns *Impl) addSubnetAddress(pn tcpip.NetworkProtocolNumber, ip netaddr.IP) {
	ns.mu.Lock()
	ns.connsOpenBySubnetIP[ip]++
	needAdd := ns.connsOpenBySubnetIP[ip] == 1
	ns.mu.Unlock()
	// Only register address into netstack for first concurrent connection.
	if needAdd {
		ns.ipstack.AddAddress(nicID, pn, tcpip.Address(ip.IPAddr().IP))
	}
}

func (ns *Impl) removeSubnetAddress(ip netaddr.IP) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.connsOpenBySubnetIP[ip]--
	// Only unregister address from netstack after last concurrent connection.
	if ns.connsOpenBySubnetIP[ip] == 0 {
		ns.ipstack.RemoveAddress(nicID, tcpip.Address(ip.IPAddr().IP))
		delete(ns.connsOpenBySubnetIP, ip)
	}
}

func ipPrefixToAddressWithPrefix(ipp netaddr.IPPrefix) tcpip.AddressWithPrefix {
	return tcpip.AddressWithPrefix{
		Address:   tcpip.Address(ipp.IP.IPAddr().IP),
		PrefixLen: int(ipp.Bits),
	}
}

func (ns *Impl) updateIPs(nm *netmap.NetworkMap) {
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nm.Addresses))
	ns.updateDNS(nm)

	oldIPs := make(map[tcpip.AddressWithPrefix]bool)
	for _, protocolAddr := range ns.ipstack.AllAddresses()[nicID] {
		oldIPs[protocolAddr.AddressWithPrefix] = true
	}
	newIPs := make(map[tcpip.AddressWithPrefix]bool)

	isAddr := map[netaddr.IPPrefix]bool{}
	for _, ipp := range nm.SelfNode.Addresses {
		isAddr[ipp] = true
	}
	for _, ipp := range nm.SelfNode.AllowedIPs {
		if ns.onlySubnets && isAddr[ipp] {
			continue
		}
		newIPs[ipPrefixToAddressWithPrefix(ipp)] = true
	}

	ipsToBeAdded := make(map[tcpip.AddressWithPrefix]bool)
	for ipp := range newIPs {
		if !oldIPs[ipp] {
			ipsToBeAdded[ipp] = true
		}
	}
	ipsToBeRemoved := make(map[tcpip.AddressWithPrefix]bool)
	for ip := range oldIPs {
		if !newIPs[ip] {
			ipsToBeRemoved[ip] = true
		}
	}
	ns.mu.Lock()
	for ip := range ns.connsOpenBySubnetIP {
		ipp := tcpip.Address(ip.IPAddr().IP).WithPrefix()
		delete(ipsToBeRemoved, ipp)
	}
	ns.mu.Unlock()

	for ipp := range ipsToBeRemoved {
		err := ns.ipstack.RemoveAddress(nicID, ipp.Address)
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", ipp, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", ipp)
		}
	}
	for ipp := range ipsToBeAdded {
		var err tcpip.Error
		if ipp.Address.To4() == "" {
			err = ns.ipstack.AddAddressWithPrefix(nicID, ipv6.ProtocolNumber, ipp)
		} else {
			err = ns.ipstack.AddAddressWithPrefix(nicID, ipv4.ProtocolNumber, ipp)
		}
		if err != nil {
			ns.logf("netstack: could not register IP %s: %v", ipp, err)
		} else {
			ns.logf("[v2] netstack: registered IP %s", ipp)
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

	// No MagicDNS name so try real DNS.
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

// isLocalIP reports whether ip is a Tailscale IP assigned to this
// node directly (but not a subnet-routed IP).
func (ns *Impl) isLocalIP(ip netaddr.IP) bool {
	return ns.atomicIsLocalIPFunc.Load().(func(netaddr.IP) bool)(ip)
}

func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if ns.onlySubnets && ns.isLocalIP(p.Dst.IP) {
		// In hybrid ("only subnets") mode, bail out early if
		// the traffic is destined for an actual Tailscale
		// address. The real host OS interface will handle it.
		return filter.Accept
	}
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
	reqDetails := r.ID()
	if debugNetstack {
		ns.logf("[v2] TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
	}
	dialAddr := reqDetails.LocalAddress
	dialNetAddr, _ := netaddr.FromStdIP(net.IP(dialAddr))
	isTailscaleIP := tsaddr.IsTailscaleIP(dialNetAddr)
	defer func() {
		if !isTailscaleIP {
			// if this is a subnet IP, we added this in before the TCP handshake
			// so netstack is happy TCP-handshaking as a subnet IP
			ns.removeSubnetAddress(dialNetAddr)
		}
	}()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	if isTailscaleIP {
		dialAddr = tcpip.Address(net.ParseIP("127.0.0.1")).To4()
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	ns.forwardTCP(c, &wq, dialAddr, reqDetails.LocalPort)
}

func (ns *Impl) forwardTCP(client *gonet.TCPConn, wq *waiter.Queue, dialAddr tcpip.Address, dialPort uint16) {
	defer client.Close()
	dialAddrStr := net.JoinHostPort(dialAddr.String(), strconv.Itoa(int(dialPort)))
	ns.logf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
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
	server, err := stdDialer.DialContext(ctx, "tcp", dialAddrStr)
	if err != nil {
		ns.logf("netstack: could not connect to local server at %s: %v", dialAddrStr, err)
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
	ns.logf("[v2] netstack: forwarder connection to %s closed", dialAddrStr)
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	reqDetails := r.ID()
	if debugNetstack {
		ns.logf("[v2] UDP ForwarderRequest: %v", stringifyTEI(reqDetails))
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("acceptUDP: could not create endpoint: %v", err)
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

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}
