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
	"os"
	"os/exec"
	"runtime"
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
	"tailscale.com/envknob"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

const debugPackets = false

var debugNetstack = envknob.Bool("TS_DEBUG_NETSTACK")

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	// ForwardTCPIn, if non-nil, handles forwarding an inbound TCP
	// connection.
	// TODO(bradfitz): provide mechanism for tsnet to reject a
	// port other than accepting it and closing it.
	ForwardTCPIn func(c net.Conn, port uint16)

	// ProcessLocalIPs is whether netstack should handle incoming
	// traffic directed at the Node.Addresses (local IPs).
	// It can only be set before calling Start.
	ProcessLocalIPs bool

	// ProcessSubnets is whether netstack should handle incoming
	// traffic destined to non-local IPs (i.e. whether it should
	// be a subnet router).
	// It can only be set before calling Start.
	ProcessSubnets bool

	ipstack   *stack.Stack
	linkEP    *channel.Endpoint
	tundev    *tstun.Wrapper
	e         wgengine.Engine
	mc        *magicsock.Conn
	logf      logger.Logf
	dialer    *tsdial.Dialer
	ctx       context.Context    // alive until Close
	ctxCancel context.CancelFunc // called on Close

	// atomicIsLocalIPFunc holds a func that reports whether an IP
	// is a local (non-subnet) Tailscale IP address of this
	// machine. It's always a non-nil func. It's changed on netmap
	// updates.
	atomicIsLocalIPFunc atomic.Value // of func(netaddr.IP) bool

	mu sync.Mutex
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netaddr.IP]int
}

const nicID = 1
const mtu = 1500

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.Wrapper, e wgengine.Engine, mc *magicsock.Conn, dialer *tsdial.Dialer) (*Impl, error) {
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
	if dialer == nil {
		return nil, errors.New("nil Dialer")
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
		dialer:              dialer,
		connsOpenBySubnetIP: make(map[netaddr.IP]int),
	}
	ns.ctx, ns.ctxCancel = context.WithCancel(context.Background())
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nil))
	return ns, nil
}

func (ns *Impl) Close() error {
	ns.ctxCancel()
	return nil
}

// wrapProtoHandler returns protocol handler h wrapped in a version
// that dynamically reconfigures ns's subnet addresses as needed for
// outbound traffic.
func (ns *Impl) wrapProtoHandler(h func(stack.TransportEndpointID, *stack.PacketBuffer) bool) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		addr := tei.LocalAddress
		ip, ok := netaddr.FromStdIP(net.IP(addr))
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}
		if !ns.isLocalIP(ip) {
			ns.addSubnetAddress(ip)
		}
		return h(tei, pb)
	}
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
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, ns.wrapProtoHandler(tcpFwd.HandlePacket))
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, ns.wrapProtoHandler(udpFwd.HandlePacket))
	go ns.injectOutbound()
	ns.tundev.PostFilterIn = ns.injectInbound
	return nil
}

func (ns *Impl) addSubnetAddress(ip netaddr.IP) {
	ns.mu.Lock()
	ns.connsOpenBySubnetIP[ip]++
	needAdd := ns.connsOpenBySubnetIP[ip] == 1
	ns.mu.Unlock()
	// Only register address into netstack for first concurrent connection.
	if needAdd {
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.Address(ip.IPAddr().IP),
				PrefixLen: int(ip.BitLen()),
			},
		}
		if ip.Is4() {
			pa.Protocol = ipv4.ProtocolNumber
		} else if ip.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
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
		Address:   tcpip.Address(ipp.IP().IPAddr().IP),
		PrefixLen: int(ipp.Bits()),
	}
}

var v4broadcast = netaddr.IPv4(255, 255, 255, 255)

func (ns *Impl) updateIPs(nm *netmap.NetworkMap) {
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nm.Addresses))

	oldIPs := make(map[tcpip.AddressWithPrefix]bool)
	for _, protocolAddr := range ns.ipstack.AllAddresses()[nicID] {
		ap := protocolAddr.AddressWithPrefix
		ip := netaddrIPFromNetstackIP(ap.Address)
		if ip == v4broadcast && ap.PrefixLen == 32 {
			// Don't delete this one later. It seems to be important.
			// Related to Issue 2642? Likely.
			continue
		}
		oldIPs[ap] = true
	}
	newIPs := make(map[tcpip.AddressWithPrefix]bool)

	isAddr := map[netaddr.IPPrefix]bool{}
	if nm.SelfNode != nil {
		for _, ipp := range nm.SelfNode.Addresses {
			isAddr[ipp] = true
		}
		for _, ipp := range nm.SelfNode.AllowedIPs {
			local := isAddr[ipp]
			if local && ns.ProcessLocalIPs || !local && ns.ProcessSubnets {
				newIPs[ipPrefixToAddressWithPrefix(ipp)] = true
			}
		}
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
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: ipp,
		}
		if ipp.Address.To4() == "" {
			pa.Protocol = ipv6.ProtocolNumber
		} else {
			pa.Protocol = ipv4.ProtocolNumber
		}
		var err tcpip.Error
		err = ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
		if err != nil {
			ns.logf("netstack: could not register IP %s: %v", ipp, err)
		} else {
			ns.logf("[v2] netstack: registered IP %s", ipp)
		}
	}
}

func (ns *Impl) DialContextTCP(ctx context.Context, ipp netaddr.IPPort) (*gonet.TCPConn, error) {
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(ipp.IP().IPAddr().IP),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.IP().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialContextTCP(ctx, ns.ipstack, remoteAddress, ipType)
}

func (ns *Impl) DialContextUDP(ctx context.Context, ipp netaddr.IPPort) (*gonet.UDPConn, error) {
	remoteAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.Address(ipp.IP().IPAddr().IP),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.IP().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialUDP(ns.ipstack, nil, remoteAddress, ipType)
}

func (ns *Impl) injectOutbound() {
	for {
		packetInfo, ok := ns.linkEP.ReadContext(ns.ctx)
		if !ok {
			if ns.ctx.Err() != nil {
				// Return without logging.
				return
			}
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
		if debugPackets {
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

// shouldProcessInbound reports whether an inbound packet should be
// handled by netstack.
func (ns *Impl) shouldProcessInbound(p *packet.Parsed, t *tstun.Wrapper) bool {
	if !ns.ProcessLocalIPs && !ns.ProcessSubnets {
		// Fast path for common case (e.g. Linux server in TUN mode) where
		// netstack isn't used at all; don't even do an isLocalIP lookup.
		return false
	}
	isLocal := ns.isLocalIP(p.Dst.IP())
	if ns.ProcessLocalIPs && isLocal {
		return true
	}
	if ns.ProcessSubnets && !isLocal {
		return true
	}
	return false
}

// setAmbientCapsRaw is non-nil on Linux for Synology, to run ping with
// CAP_NET_RAW from tailscaled's binary.
var setAmbientCapsRaw func(*exec.Cmd)

var userPingSem = syncs.NewSemaphore(20) // 20 child ping processes at once

var isSynology = runtime.GOOS == "linux" && distro.Get() == distro.Synology

// userPing tried to ping dstIP and if it succeeds, injects pingResPkt
// into the tundev.
//
// It's used in userspace/netstack mode when we don't have kernel
// support or raw socket access. As such, this does the dumbest thing
// that can work: runs the ping command. It's not super efficient, so
// it bounds the number of pings going on at once. The idea is that
// people only use ping occasionally to see if their internet's working
// so this doesn't need to be great.
//
// TODO(bradfitz): when we're running on Windows as the system user, use
// raw socket APIs instead of ping child processes.
func (ns *Impl) userPing(dstIP netaddr.IP, pingResPkt []byte) {
	if !userPingSem.TryAcquire() {
		return
	}
	defer userPingSem.Release()

	t0 := time.Now()
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("ping", "-n", "1", "-w", "3000", dstIP.String()).Run()
	case "darwin":
		// Note: 2000 ms is actually 1 second + 2,000
		// milliseconds extra for 3 seconds total.
		// See https://github.com/tailscale/tailscale/pull/3753 for details.
		err = exec.Command("ping", "-c", "1", "-W", "2000", dstIP.String()).Run()
	case "android":
		ping := "/system/bin/ping"
		if dstIP.Is6() {
			ping = "/system/bin/ping6"
		}
		err = exec.Command(ping, "-c", "1", "-w", "3", dstIP.String()).Run()
	default:
		ping := "ping"
		if isSynology {
			ping = "/bin/ping"
		}
		cmd := exec.Command(ping, "-c", "1", "-W", "3", dstIP.String())
		if isSynology && os.Getuid() != 0 {
			// On DSM7 we run as non-root and need to pass
			// CAP_NET_RAW if our binary has it.
			setAmbientCapsRaw(cmd)
		}
		err = cmd.Run()
	}
	d := time.Since(t0)
	if err != nil {
		if d < time.Second/2 {
			// If it failed quicker than the 3 second
			// timeout we gave above (500 ms is a
			// reasonable threshold), then assume the ping
			// failed for problems finding/running
			// ping. We don't want to log if the host is
			// just down.
			ns.logf("exec ping of %v failed in %v: %v", dstIP, d, err)
		}
		return
	}
	if debugNetstack {
		ns.logf("exec pinged %v in %v", dstIP, time.Since(t0))
	}
	if err := ns.tundev.InjectOutbound(pingResPkt); err != nil {
		ns.logf("InjectOutbound ping response: %v", err)
	}
}

func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if !ns.shouldProcessInbound(p, t) {
		// Let the host network stack (if any) deal with it.
		return filter.Accept
	}

	destIP := p.Dst.IP()
	if p.IsEchoRequest() && ns.ProcessSubnets && !tsaddr.IsTailscaleIP(destIP) {
		var pong []byte // the reply to the ping, if our relayed ping works
		if destIP.Is4() {
			h := p.ICMP4Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		} else if destIP.Is6() {
			h := p.ICMP6Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		}
		go ns.userPing(destIP, pong)
		return filter.DropSilently
	}

	var pn tcpip.NetworkProtocolNumber
	switch p.IPVersion {
	case 4:
		pn = header.IPv4ProtocolNumber
	case 6:
		pn = header.IPv6ProtocolNumber
	}
	p.RemoveECNBits() // Issue 2642
	if debugPackets {
		ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	}
	vv := buffer.View(append([]byte(nil), p.Buffer()...)).ToVectorisedView()
	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: vv,
	})
	ns.linkEP.InjectInbound(pn, packetBuf)
	packetBuf.DecRef()

	// We've now delivered this to netstack, so we're done.
	// Instead of returning a filter.Accept here (which would also
	// potentially deliver it to the host OS), and instead of
	// filter.Drop (which would log about rejected traffic),
	// instead return filter.DropSilently which just quietly stops
	// processing it in the tstun TUN wrapper.
	return filter.DropSilently
}

func netaddrIPFromNetstackIP(s tcpip.Address) netaddr.IP {
	switch len(s) {
	case 4:
		return netaddr.IPv4(s[0], s[1], s[2], s[3])
	case 16:
		var a [16]byte
		copy(a[:], s)
		return netaddr.IPFrom16(a)
	}
	return netaddr.IP{}
}

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()
	if debugNetstack {
		ns.logf("[v2] TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
	}
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	if !clientRemoteIP.IsValid() {
		ns.logf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
		r.Complete(true) // sends a RST
		return
	}

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	isTailscaleIP := tsaddr.IsTailscaleIP(dialIP)
	defer func() {
		if !isTailscaleIP {
			// if this is a subnet IP, we added this in before the TCP handshake
			// so netstack is happy TCP-handshaking as a subnet IP
			ns.removeSubnetAddress(dialIP)
		}
	}()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
		r.Complete(true) // sends a RST
		return
	}
	r.Complete(false)

	// The ForwarderRequest.CreateEndpoint above asynchronously
	// starts the TCP handshake. Note that the gonet.TCPConn
	// methods c.RemoteAddr() and c.LocalAddr() will return nil
	// until the handshake actually completes. But we have the
	// remote address in reqDetails instead, so we don't use
	// gonet.TCPConn.RemoteAddr. The byte copies in both
	// directions to/from the gonet.TCPConn in forwardTCP will
	// block until the TCP handshake is complete.
	c := gonet.NewTCPConn(&wq, ep)

	if ns.ForwardTCPIn != nil {
		ns.ForwardTCPIn(c, reqDetails.LocalPort)
		return
	}
	if isTailscaleIP {
		dialIP = netaddr.IPv4(127, 0, 0, 1)
	}
	dialAddr := netaddr.IPPortFrom(dialIP, uint16(reqDetails.LocalPort))
	ns.forwardTCP(c, clientRemoteIP, &wq, dialAddr)
}

func (ns *Impl) forwardTCP(client *gonet.TCPConn, clientRemoteIP netaddr.IP, wq *waiter.Queue, dialAddr netaddr.IPPort) {
	defer client.Close()
	dialAddrStr := dialAddr.String()
	if debugNetstack {
		ns.logf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			if debugNetstack {
				ns.logf("[v2] netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
			}
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
	sess := r.ID()
	if debugNetstack {
		ns.logf("[v2] UDP ForwarderRequest: %v", stringifyTEI(sess))
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("acceptUDP: could not create endpoint: %v", err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		return
	}

	c := gonet.NewUDPConn(ns.ipstack, &wq, ep)
	go ns.forwardUDP(c, &wq, srcAddr, dstAddr)
}

// forwardUDP proxies between client (with addr clientAddr) and dstAddr.
//
// dstAddr may be either a local Tailscale IP, in which we case we proxy to
// 127.0.0.1, or any other IP (from an advertised subnet), in which case we
// proxy to it directly.
func (ns *Impl) forwardUDP(client *gonet.UDPConn, wq *waiter.Queue, clientAddr, dstAddr netaddr.IPPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	if debugNetstack {
		ns.logf("[v2] netstack: forwarding incoming UDP connection on port %v", port)
	}

	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := ns.isLocalIP(dstAddr.IP())
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else {
		backendRemoteAddr = dstAddr.UDPAddr()
		if dstAddr.IP().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}

	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		ns.logf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			ns.logf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)
	backendLocalIPPort, ok := netaddr.FromStdAddr(backendListenAddr.IP, backendLocalAddr.Port, backendLocalAddr.Zone)
	if !ok {
		ns.logf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	if isLocal {
		ns.e.RegisterIPPortIdentity(backendLocalIPPort, dstAddr.IP())
	}
	ctx, cancel := context.WithCancel(context.Background())

	idleTimeout := 2 * time.Minute
	if port == 53 {
		// Make DNS packet copies time out much sooner.
		//
		// TODO(bradfitz): make DNS queries over UDP forwarding even
		// cheaper by adding an additional idleTimeout post-DNS-reply.
		// For instance, after the DNS response goes back out, then only
		// wait a few seconds (or zero, really)
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		if isLocal {
			ns.e.UnregisterIPPortIdentity(backendLocalIPPort)
		}
		ns.logf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(idleTimeout)
	}
	startPacketCopy(ctx, cancel, client, clientAddr.UDPAddr(), backendConn, ns.logf, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, ns.logf, extend)
	if isLocal {
		// Wait for the copies to be done before decrementing the
		// subnet address count to potentially remove the route.
		<-ctx.Done()
		ns.removeSubnetAddress(dstAddr.IP())
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, logf logger.Logf, extend func()) {
	if debugNetstack {
		logf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	}
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

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netaddr.IPPort, ok bool) {
	return netaddr.FromStdAddr(net.IP(a), int(port), "") // TODO(bradfitz): can do without allocs
}
