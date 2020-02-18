// Copyright 2019 Tailscale & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/derp/derphttp"
	"tailscale.com/stun"
	"tailscale.com/stunner"
	"tailscale.com/types/key"
)

// A Conn routes UDP packets and actively manages a list of its endpoints.
// It implements wireguard/device.Bind.
type Conn struct {
	pconn         *RebindingUDPConn
	pconnPort     uint16
	stunServers   []string
	derpServer    string
	startEpUpdate chan struct{} // send to trigger endpoint update
	epFunc        func(endpoints []string)
	logf          func(format string, args ...interface{})

	epUpdateCtx    context.Context // endpoint updater context
	epUpdateCancel func()          // the func to cancel epUpdateCtx

	// indexedAddrs is a map of every remote ip:port to a priority
	// list of endpoint addresses for a peer.
	// The priority list is provided by wgengine configuration.
	//
	// Given a wgcfg describing:
	//	machineA: 10.0.0.1:1, 10.0.0.2:2
	//	machineB: 10.0.0.3:3
	// the indexedAddrs map contains:
	//	10.0.0.1:1 -> [10.0.0.1:1, 10.0.0.2:2], index:0
	//	10.0.0.2:2 -> [10.0.0.1:1, 10.0.0.2:2], index:1
	//	10.0.0.3:3 -> [10.0.0.3:3],             index:0
	indexedAddrsMu sync.Mutex
	indexedAddrs   map[udpAddr]indexedAddrSet

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	derpMu sync.Mutex
	derp   *derphttp.Client
}

// udpAddr is the key in the indexedAddrs map.
// It maps an ip:port onto an indexedAddr.
type udpAddr struct {
	ip   wgcfg.IP
	port uint16
}

// indexedAddrSet is an AddrSet (a priority list of ip:ports for a peer and the
// current favored ip:port for communicating with the peer) and an index
// number saying which element of the priority list is this map entry.
type indexedAddrSet struct {
	addr  *AddrSet
	index int // index of map key in addr.Addrs
}

// DefaultPort is the default port to listen on.
// The current default (zero) means to auto-select a random free port.
const DefaultPort = 0

const DefaultDERP = "https://derp.tailscale.com/derp"

var DefaultSTUN = []string{
	"stun.l.google.com:19302",
	"stun3.l.google.com:19302",
}

// Options contains options for Listen.
type Options struct {
	// Port is the port to listen on.
	// Zero means to pick one automatically.
	Port uint16

	STUN []string
	DERP string

	// EndpointsFunc optionally provides a func to be called when
	// endpoints change. The called func does not own the slice.
	EndpointsFunc func(endpoint []string)
}

func (o *Options) endpointsFunc() func([]string) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]string) {}
	}
	return o.EndpointsFunc
}

// Listen creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
func Listen(opts Options) (*Conn, error) {
	var packetConn net.PacketConn
	var err error
	if opts.Port == 0 {
		// Our choice of port. Start with DefaultPort.
		// If unavailable, pick any port.
		want := fmt.Sprintf(":%d", DefaultPort)
		log.Printf("magicsock: bind: trying %v\n", want)
		packetConn, err = net.ListenPacket("udp4", want)
		if err != nil {
			want = ":0"
			log.Printf("magicsock: bind: falling back to %v (%v)\n", want, err)
			packetConn, err = net.ListenPacket("udp4", want)
		}
	} else {
		packetConn, err = net.ListenPacket("udp4", fmt.Sprintf(":%d", opts.Port))
	}
	if err != nil {
		return nil, fmt.Errorf("magicsock.Listen: %v", err)
	}

	epUpdateCtx, epUpdateCancel := context.WithCancel(context.Background())
	c := &Conn{
		pconn:          new(RebindingUDPConn),
		stunServers:    append([]string{}, opts.STUN...),
		derpServer:     opts.DERP,
		startEpUpdate:  make(chan struct{}, 1),
		epUpdateCtx:    epUpdateCtx,
		epUpdateCancel: epUpdateCancel,
		epFunc:         opts.endpointsFunc(),
		logf:           log.Printf,
		indexedAddrs:   make(map[udpAddr]indexedAddrSet),
	}
	c.ignoreSTUNPackets()
	c.pconn.Reset(packetConn.(*net.UDPConn))
	c.reSTUN()
	go c.epUpdate(epUpdateCtx)
	return c, nil
}

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, *net.UDPAddr) {})
}

// epUpdate runs in its own goroutine until ctx is shut down.
// Whenever c.startEpUpdate receives a value, it starts an
// STUN endpoint lookup.
func (c *Conn) epUpdate(ctx context.Context) {
	var lastEndpoints []string
	var lastCancel func()
	var lastDone chan struct{}
	for {
		select {
		case <-ctx.Done():
			if lastCancel != nil {
				lastCancel()
			}
			return
		case <-c.startEpUpdate:
		}

		if lastCancel != nil {
			lastCancel()
			<-lastDone
		}
		var epCtx context.Context
		epCtx, lastCancel = context.WithCancel(ctx)
		lastDone = make(chan struct{})

		go func() {
			defer close(lastDone)
			endpoints, err := c.determineEndpoints(epCtx)
			if err != nil {
				c.logf("magicsock.Conn: endpoint update failed: %v", err)
				// TODO(crawshaw): are there any conditions under which
				// we should trigger a retry based on the error here?
				return
			}
			if stringsEqual(endpoints, lastEndpoints) {
				return
			}
			lastEndpoints = endpoints
			c.epFunc(endpoints)
		}()
	}
}

// determineEndpoints returns the machine's endpoint addresses. It
// does a STUN lookup to determine its public address.
func (c *Conn) determineEndpoints(ctx context.Context) ([]string, error) {
	var (
		alreadyMu sync.Mutex
		already   = make(map[string]bool) // endpoint -> true
	)
	var eps []string // unique endpoints

	addAddr := func(s, reason string) {
		log.Printf("magicsock: found local %s (%s)\n", s, reason)

		alreadyMu.Lock()
		defer alreadyMu.Unlock()
		if !already[s] {
			already[s] = true
			eps = append(eps, s)
		}
	}

	s := &stunner.Stunner{
		Send:     c.pconn.WriteTo,
		Endpoint: func(s string) { addAddr(s, "stun") },
		Servers:  c.stunServers,
		Logf:     c.logf,
	}

	c.stunReceiveFunc.Store(s.Receive)

	if err := s.Run(ctx); err != nil {
		return nil, err
	}

	c.ignoreSTUNPackets()

	if localAddr := c.pconn.LocalAddr(); localAddr.IP.IsUnspecified() {
		localPort := fmt.Sprintf("%d", localAddr.Port)
		loopbacks, err := localAddresses(localPort, func(s string) {
			addAddr(s, "localAddresses")
		})
		if err != nil {
			return nil, err
		}
		if len(eps) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			for _, s := range loopbacks {
				addAddr(s, "loopback")
			}
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(localAddr.String(), "socket")
	}

	// Note: the endpoints are intentionally returned in priority order,
	// from "farthest but most reliable" to "closest but least
	// reliable." Addresses returned from STUN should be globally
	// addressable, but might go farther on the network than necessary.
	// Local interface addresses might have lower latency, but not be
	// globally addressable.
	//
	// The STUN address(es) are always first so that legacy wireguard
	// can use eps[0] as its only known endpoint address (although that's
	// obviously non-ideal).
	return eps, nil
}

func stringsEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func localAddresses(localPort string, addAddr func(s string)) ([]string, error) {
	var loopback []string

	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		if (i.Flags & net.FlagUp) == 0 {
			// Down interfaces don't count
			continue
		}
		ifcIsLoopback := (i.Flags & net.FlagLoopback) != 0

		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				// TODO(crawshaw): IPv6 support.
				// Easy to do here, but we need good endpoint ordering logic.
				ip := v.IP.To4()
				if ip == nil {
					continue
				}
				// TODO(apenwarr): don't special case cgNAT.
				// In the general wireguard case, it might
				// very well be something we can route to
				// directly, because both nodes are
				// behind the same CGNAT router.
				if cgNAT.Contains(ip) {
					continue
				}
				if linkLocalIPv4.Contains(ip) {
					continue
				}
				ep := net.JoinHostPort(ip.String(), localPort)
				if ip.IsLoopback() || ifcIsLoopback {
					loopback = append(loopback, ep)
					continue
				}
				addAddr(ep)
			}
		}
	}
	return loopback, nil
}

var cgNAT = func() *net.IPNet {
	_, ipNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	return ipNet
}()

var linkLocalIPv4 = func() *net.IPNet {
	_, ipNet, err := net.ParseCIDR("169.254.0.0/16")
	if err != nil {
		panic(err)
	}
	return ipNet
}()

func (c *Conn) LocalPort() uint16 {
	laddr := c.pconn.LocalAddr()
	return uint16(laddr.Port)
}

func (c *Conn) Send(b []byte, ep device.Endpoint) error {
	a := ep.(*AddrSet)

	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case device.MessageInitiationType, device.MessageResponseType, device.MessageCookieReplyType:
		// Part of the wireguard handshake.
		// Send to every potential endpoint we have for a peer.
		a.mu.Lock()
		roamAddr := a.roamAddr
		a.mu.Unlock()

		var err error
		var success bool
		if roamAddr != nil {
			_, err = c.pconn.WriteTo(b, roamAddr)
			if err == nil {
				success = true
			}
		}
		for i := len(a.addrs) - 1; i >= 0; i-- {
			addr := &a.addrs[i]
			_, err = c.pconn.WriteTo(b, addr)
			if err == nil {
				success = true
			}
		}

		if msgType == device.MessageInitiationType {
			// Send initial handshake messages via DERP.
			c.derpMu.Lock()
			derp := c.derp
			c.derpMu.Unlock()

			if derp != nil {
				if err := derp.Send(a.publicKey, b); err != nil {
					log.Printf("derp send failed: %v", err)
				}
			}
		}

		if success {
			return nil
		}
	}

	// Write to the highest-priority address we have seen so far.
	_, err := c.pconn.WriteTo(b, a.dst())
	return err
}

func (c *Conn) findIndexedAddrSet(addr *net.UDPAddr) (addrSet *AddrSet, index int) {
	var epAddr udpAddr
	copy(epAddr.ip.Addr[:], addr.IP.To16())
	epAddr.port = uint16(addr.Port)

	c.indexedAddrsMu.Lock()
	defer c.indexedAddrsMu.Unlock()

	indAddr := c.indexedAddrs[epAddr]
	if indAddr.addr == nil {
		return nil, 0
	}
	return indAddr.addr, indAddr.index
}

func (c *Conn) ReceiveIPv4(b []byte) (n int, ep device.Endpoint, addr *net.UDPAddr, err error) {
	// Read a packet, and process any STUN packets before returning.
	for {
		var pAddr net.Addr
		n, pAddr, err = c.pconn.ReadFrom(b)
		if err != nil {
			return n, nil, nil, err
		}
		addr = pAddr.(*net.UDPAddr)
		addr.IP = addr.IP.To4()

		if !stun.Is(b[:n]) {
			break
		}
		c.stunReceiveFunc.Load().(func([]byte, *net.UDPAddr))(b, addr)
	}

	addrSet, _ := c.findIndexedAddrSet(addr)
	if addrSet == nil {
		// The peer that sent this packet has roamed beyond the
		// knowledge provided by the control server.
		// If the packet is valid wireguard will call UpdateDst
		// on the original endpoint using this addr.
		return n, (*singleEndpoint)(addr), addr, nil
	}
	return n, addrSet, addr, nil
}

func (c *Conn) ReceiveIPv6(buff []byte) (int, device.Endpoint, *net.UDPAddr, error) {
	// TODO(crawshaw): IPv6 support
	return 0, nil, nil, syscall.EAFNOSUPPORT
}

func (c *Conn) SetPrivateKey(privateKey wgcfg.PrivateKey) error {
	if c.derpServer == "" {
		return nil
	}

	derp, err := derphttp.NewClient(key.Private(privateKey), c.derpServer, log.Printf)
	if err != nil {
		return err
	}
	go func() {
		var b [64 << 10]byte
		for {
			n, err := derp.Recv(b[:])
			if err != nil {
				if err == derphttp.ErrClientClosed {
					return
				}
				log.Printf("derp.Recv: %v", err)
				time.Sleep(250 * time.Millisecond)
			}

			c.reSTUN()

			addr := c.pconn.LocalAddr()
			if _, err := c.pconn.WriteToUDP(b[:n], addr); err != nil {
				log.Printf("%v", err)
			}
		}
	}()

	c.derpMu.Lock()
	if c.derp != nil {
		if err := c.derp.Close(); err != nil {
			log.Printf("derp.Close: %v", err)
		}
	}
	c.derp = derp
	c.derpMu.Unlock()

	return nil
}

func (c *Conn) SetMark(value uint32) error { return nil }

func (c *Conn) Close() error {
	c.epUpdateCancel()
	return c.pconn.Close()
}

func (c *Conn) reSTUN() {
	select {
	case c.startEpUpdate <- struct{}{}:
	case <-c.epUpdateCtx.Done():
	}
}

func (c *Conn) LinkChange() {
	defer c.reSTUN()

	if c.pconnPort != 0 {
		c.pconn.mu.Lock()
		if err := c.pconn.pconn.Close(); err != nil {
			log.Printf("magicsock: link change close failed: %v", err)
		}
		packetConn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", c.pconnPort))
		if err == nil {
			log.Printf("magicsock: link change rebound port: %d", c.pconnPort)
			c.pconn.pconn = packetConn.(*net.UDPConn)
			c.pconn.mu.Unlock()
			return
		}
		log.Printf("magicsock: link change unable to bind fixed port %d: %v, falling back to random port", c.pconnPort, err)
		c.pconn.mu.Unlock()
	}

	log.Printf("magicsock: link change, binding new port")
	packetConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Printf("magicsock: link change failed to bind new port: %v", err)
		return
	}
	c.pconn.Reset(packetConn.(*net.UDPConn))
}

// AddrSet is a set of UDP addresses that implements wireguard/device.Endpoint.
type AddrSet struct {
	publicKey key.Public    // peer public key used for DERP communication
	addrs     []net.UDPAddr // ordered priority list provided by wgengine

	mu       sync.Mutex   // guards roamAddr and curAddr
	roamAddr *net.UDPAddr // peer addr determined from incoming packets
	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int
}

var noAddr = &net.UDPAddr{
	IP:   net.ParseIP("127.127.127.127"),
	Port: 127,
}

func (a *AddrSet) dst() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return &a.addrs[i]
}

// packUDPAddr packs a UDPAddr in the form wanted by WireGuard.
func packUDPAddr(ua *net.UDPAddr) []byte {
	ip := ua.IP.To4()
	if ip == nil {
		ip = ua.IP
	}
	b := make([]byte, 0, len(ip)+2)
	b = append(b, ip...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packUDPAddr(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP
}
func (a *AddrSet) SrcIP() net.IP       { return nil }
func (a *AddrSet) SrcToString() string { return "" }
func (a *AddrSet) ClearSrc()           {}

func (a *AddrSet) UpdateDst(new *net.UDPAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		if equalUDPAddr(a.roamAddr, new) {
			// Packet from the current roaming address, no logging.
			// This is a hot path for established connections.
			return nil
		}
	} else if a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	index := -1
	for i := range a.addrs {
		if equalUDPAddr(new, &a.addrs[i]) {
			index = i
			break
		}
	}

	publicKey := wgcfg.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.addrs[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			log.Printf("magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			log.Printf("magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = new

	case a.roamAddr != nil:
		log.Printf("magicsock: rx %s from known %s (%d), replacs roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.curAddr = index

	case a.curAddr == -1:
		log.Printf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index

	case index < a.curAddr:
		log.Printf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)

	default: // index > a.curAddr
		log.Printf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
	}

	return nil
}

func equalUDPAddr(x, y *net.UDPAddr) bool {
	return x.Port == y.Port && x.IP.Equal(y.IP)
}

func (a *AddrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		fmt.Fprintf(buf, "roam:%s:%d", a.roamAddr.IP, a.roamAddr.Port)
	}
	for i, addr := range a.addrs {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		fmt.Fprintf(buf, "%s:%d", addr.IP, addr.Port)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (a *AddrSet) Addrs() []wgcfg.Endpoint {
	var eps []wgcfg.Endpoint
	for _, addr := range a.addrs {
		eps = append(eps, wgcfg.Endpoint{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roamAddr != nil {
		eps = append(eps, wgcfg.Endpoint{
			Host: a.roamAddr.IP.String(),
			Port: uint16(a.roamAddr.Port),
		})
	}
	return eps
}

// CreateEndpoint is called by WireGuard to connect to an endpoint.
// The key is the public key of the peer and addrs is a
// comma-separated list of UDP ip:ports.
func (c *Conn) CreateEndpoint(key [32]byte, addrs string) (device.Endpoint, error) {
	pk := wgcfg.Key(key)
	log.Printf("magicsock: CreateEndpoint: key=%s: %s", pk.ShortString(), addrs)
	a := &AddrSet{
		publicKey: key,
		curAddr:   -1,
	}

	if addrs != "" {
		for _, ep := range strings.Split(addrs, ",") {
			addr, err := net.ResolveUDPAddr("udp", ep)
			if err != nil {
				return nil, err
			}
			if ip4 := addr.IP.To4(); ip4 != nil {
				addr.IP = ip4
			}
			a.addrs = append(a.addrs, *addr)
		}
	}

	c.indexedAddrsMu.Lock()
	for i, addr := range a.addrs {
		var epAddr udpAddr
		copy(epAddr.ip.Addr[:], addr.IP.To16())
		epAddr.port = uint16(addr.Port)
		c.indexedAddrs[epAddr] = indexedAddrSet{
			addr:  a,
			index: i,
		}
	}
	c.indexedAddrsMu.Unlock()

	return a, nil
}

type singleEndpoint net.UDPAddr

func (e *singleEndpoint) ClearSrc()           {}
func (e *singleEndpoint) DstIP() net.IP       { return (*net.UDPAddr)(e).IP }
func (e *singleEndpoint) SrcIP() net.IP       { return nil }
func (e *singleEndpoint) SrcToString() string { return "" }
func (e *singleEndpoint) DstToString() string { return (*net.UDPAddr)(e).String() }
func (e *singleEndpoint) DstToBytes() []byte  { return packUDPAddr((*net.UDPAddr)(e)) }
func (e *singleEndpoint) UpdateDst(dst *net.UDPAddr) error {
	return fmt.Errorf("magicsock.singleEndpoint(%s).UpdateDst(%s): should never be called", (*net.UDPAddr)(e), dst)
}
func (e *singleEndpoint) Addrs() []wgcfg.Endpoint {
	return []wgcfg.Endpoint{{
		Host: e.IP.String(),
		Port: uint16(e.Port),
	}}
}

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	mu    sync.Mutex
	pconn *net.UDPConn
}

func (c *RebindingUDPConn) Reset(pconn *net.UDPConn) {
	c.mu.Lock()
	old := c.pconn
	c.pconn = pconn
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, addr, err := pconn.ReadFrom(b)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, addr, err
	}
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.Close()
}

func (c *RebindingUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteToUDP(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteTo(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}
