// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//lint:file-ignore U1000 in development
//lint:file-ignore S1000 in development

// Package natlab lets us simulate different types of networks all
// in-memory without running VMs or requiring root, etc. Despite the
// name, it does more than just NATs. But NATs are the most
// interesting.
package natlab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"inet.af/netaddr"
)

var traceOn, _ = strconv.ParseBool(os.Getenv("NATLAB_TRACE"))

func trace(p []byte, msg string, args ...interface{}) {
	if !traceOn {
		return
	}
	id := packetShort(p)
	as := []interface{}{id}
	as = append(as, args...)
	fmt.Fprintf(os.Stderr, "[%s] "+msg+"\n", as...)
}

// packetShort returns a short identifier for a packet payload,
// suitable for pritning trace information.
func packetShort(p []byte) string {
	s := sha256.Sum256(p)
	return base64.RawStdEncoding.EncodeToString(s[:])[:4]
}

func mustPrefix(s string) netaddr.IPPrefix {
	ipp, err := netaddr.ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}
	return ipp
}

// NewInternet returns a network that simulates the internet.
func NewInternet() *Network {
	return &Network{
		Name:    "internet",
		Prefix4: mustPrefix("203.0.113.0/24"), // documentation netblock that looks Internet-y
		Prefix6: mustPrefix("fc00:52::/64"),
	}
}

type Network struct {
	Name    string
	Prefix4 netaddr.IPPrefix
	Prefix6 netaddr.IPPrefix

	mu        sync.Mutex
	machine   map[netaddr.IP]*Interface
	defaultGW *Interface // optional
	lastV4    netaddr.IP
	lastV6    netaddr.IP
}

func (n *Network) SetDefaultGateway(gwIf *Interface) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.defaultGW = gwIf
}

func (n *Network) addMachineLocked(ip netaddr.IP, iface *Interface) {
	if iface == nil {
		return // for tests
	}
	if n.machine == nil {
		n.machine = map[netaddr.IP]*Interface{}
	}
	n.machine[ip] = iface
}

func (n *Network) allocIPv4(iface *Interface) netaddr.IP {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Prefix4.IsZero() {
		return netaddr.IP{}
	}
	if n.lastV4.IsZero() {
		n.lastV4 = n.Prefix4.IP
	}
	a := n.lastV4.As16()
	addOne(&a, 15)
	n.lastV4 = netaddr.IPFrom16(a)
	if !n.Prefix4.Contains(n.lastV4) {
		panic("pool exhausted")
	}
	n.addMachineLocked(n.lastV4, iface)
	return n.lastV4
}

func (n *Network) allocIPv6(iface *Interface) netaddr.IP {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Prefix6.IsZero() {
		return netaddr.IP{}
	}
	if n.lastV6.IsZero() {
		n.lastV6 = n.Prefix6.IP
	}
	a := n.lastV6.As16()
	addOne(&a, 15)
	n.lastV6 = netaddr.IPFrom16(a)
	if !n.Prefix6.Contains(n.lastV6) {
		panic("pool exhausted")
	}
	n.addMachineLocked(n.lastV6, iface)
	return n.lastV6
}

func addOne(a *[16]byte, index int) {
	if v := a[index]; v < 255 {
		a[index]++
	} else {
		a[index] = 0
		addOne(a, index-1)
	}
}

func (n *Network) write(p []byte, dst, src netaddr.IPPort) (num int, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	iface, ok := n.machine[dst.IP]
	if !ok {
		if n.defaultGW == nil {
			trace(p, "net=%s dropped, no route to %v", n.Name, dst.IP)
			return len(p), nil
		}
		iface = n.defaultGW
	}

	// Pretend it went across the network. Make a copy so nobody
	// can later mess with caller's memory.
	trace(p, "net=%s src=%v dst=%v -> mach=%s iface=%s", n.Name, src, dst, iface.machine.Name, iface.name)
	pcopy := append([]byte(nil), p...)
	go iface.machine.deliverIncomingPacket(pcopy, iface, dst, src)
	return len(p), nil
}

type Interface struct {
	machine *Machine
	net     *Network
	name    string       // optional
	ips     []netaddr.IP // static; not mutated once created
}

// V4 returns the machine's first IPv4 address, or the zero value if none.
func (f *Interface) V4() netaddr.IP { return f.pickIP(netaddr.IP.Is4) }

// V6 returns the machine's first IPv6 address, or the zero value if none.
func (f *Interface) V6() netaddr.IP { return f.pickIP(netaddr.IP.Is6) }

func (f *Interface) pickIP(pred func(netaddr.IP) bool) netaddr.IP {
	for _, ip := range f.ips {
		if pred(ip) {
			return ip
		}
	}
	return netaddr.IP{}
}

func (f *Interface) String() string {
	// TODO: make this all better
	if f.name != "" {
		return f.name
	}
	return fmt.Sprintf("unamed-interface-on-network-%p", f.net)
}

// Contains reports whether f contains ip as an IP.
func (f *Interface) Contains(ip netaddr.IP) bool {
	for _, v := range f.ips {
		if ip == v {
			return true
		}
	}
	return false
}

type routeEntry struct {
	prefix netaddr.IPPrefix
	iface  *Interface
}

// A PacketVerdict is a decision of what to do with a packet.
type PacketVerdict int

const (
	// Continue means the packet should be processed by the "local
	// sockets" logic of the Machine.
	Continue PacketVerdict = iota
	// Drop means the packet should not be handled further.
	Drop
)

func (v PacketVerdict) String() string {
	switch v {
	case Continue:
		return "Continue"
	case Drop:
		return "Drop"
	default:
		return fmt.Sprintf("<unknown verdict %d>", v)
	}
}

// A PacketHandler is a function that can process packets.
type PacketHandler func(p []byte, inIf *Interface, dst, src netaddr.IPPort) PacketVerdict

// A Machine is a representation of an operating system's network
// stack. It has a network routing table and can have multiple
// attached networks. The zero value is valid, but lacks any
// networking capability until Attach is called.
type Machine struct {
	// Name is a pretty name for debugging and packet tracing. It need
	// not be globally unique.
	Name string

	// HandlePacket, if not nil, is a function that gets invoked for
	// every packet this Machine receives. Returns a verdict for how
	// the packet should continue to be handled (or not).
	//
	// This can be used to implement things like stateful firewalls
	// and NAT boxes.
	HandlePacket PacketHandler

	mu         sync.Mutex
	interfaces []*Interface
	routes     []routeEntry // sorted by longest prefix to shortest

	conns4 map[netaddr.IPPort]*conn // conns that want IPv4 packets
	conns6 map[netaddr.IPPort]*conn // conns that want IPv6 packets
}

// Inject transmits p from src to dst, without the need for a local socket.
// It's useful for implementing e.g. NAT boxes that need to mangle IPs.
func (m *Machine) Inject(p []byte, dst, src netaddr.IPPort) error {
	trace(p, "mach=%s src=%s dst=%s packet injected", m.Name, src, dst)
	_, err := m.writePacket(p, dst, src)
	return err
}

func (m *Machine) deliverIncomingPacket(p []byte, iface *Interface, dst, src netaddr.IPPort) {
	// TODO: can't hold lock while handling packet. This is safe as
	// long as you set HandlePacket before traffic starts flowing.
	if m.HandlePacket != nil {
		verdict := m.HandlePacket(p, iface, dst, src)
		trace(p, "mach=%s src=%v dst=%v packethandler verdict=%s", m.Name, src, dst, verdict)
		if verdict == Drop {
			// Custom packet handler ate the packet, we're done.
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	conns := m.conns4
	if dst.IP.Is6() {
		conns = m.conns6
	}
	possibleDsts := []netaddr.IPPort{
		dst,
		netaddr.IPPort{IP: v6unspec, Port: dst.Port},
		netaddr.IPPort{IP: v4unspec, Port: dst.Port},
	}
	for _, dest := range possibleDsts {
		c, ok := conns[dest]
		if !ok {
			continue
		}
		select {
		case c.in <- incomingPacket{src: src, p: p}:
			trace(p, "mach=%s src=%v dst=%v queued to conn", m.Name, src, dst)
		default:
			trace(p, "mach=%s src=%v dst=%v dropped, queue overflow", m.Name, src, dst)
			// Queue overflow. Just drop it.
		}
		return
	}
	trace(p, "mach=%s src=%v dst=%v dropped, no listening conn", m.Name, src, dst)
}

func unspecOf(ip netaddr.IP) netaddr.IP {
	if ip.Is4() {
		return v4unspec
	}
	if ip.Is6() {
		return v6unspec
	}
	panic(fmt.Sprintf("bogus IP %#v", ip))
}

// Attach adds an interface to a machine.
//
// The first interface added to a Machine becomes that machine's
// default route.
func (m *Machine) Attach(interfaceName string, n *Network) *Interface {
	f := &Interface{
		machine: m,
		net:     n,
		name:    interfaceName,
	}
	if ip := n.allocIPv4(f); !ip.IsZero() {
		f.ips = append(f.ips, ip)
	}
	if ip := n.allocIPv6(f); !ip.IsZero() {
		f.ips = append(f.ips, ip)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.interfaces = append(m.interfaces, f)
	if len(m.interfaces) == 1 {
		m.routes = append(m.routes,
			routeEntry{
				prefix: mustPrefix("0.0.0.0/0"),
				iface:  f,
			},
			routeEntry{
				prefix: mustPrefix("::/0"),
				iface:  f,
			})
	} else {
		if !n.Prefix4.IsZero() {
			m.routes = append(m.routes, routeEntry{
				prefix: n.Prefix4,
				iface:  f,
			})
		}
		if !n.Prefix6.IsZero() {
			m.routes = append(m.routes, routeEntry{
				prefix: n.Prefix6,
				iface:  f,
			})
		}
	}
	sort.Slice(m.routes, func(i, j int) bool {
		return m.routes[i].prefix.Bits > m.routes[j].prefix.Bits
	})

	return f
}

var (
	v4unspec = netaddr.IPv4(0, 0, 0, 0)
	v6unspec = netaddr.IPv6Unspecified()
)

func (m *Machine) writePacket(p []byte, dst, src netaddr.IPPort) (n int, err error) {
	iface, err := m.interfaceForIP(dst.IP)
	if err != nil {
		trace(p, "%v", err)
		return 0, err
	}
	origSrcIP := src.IP
	switch {
	case src.IP == v4unspec:
		src.IP = iface.V4()
	case src.IP == v6unspec:
		// v6unspec in Go means "any src, but match address families"
		if dst.IP.Is6() {
			src.IP = iface.V6()
		} else if dst.IP.Is4() {
			src.IP = iface.V4()
		}
	default:
		if !iface.Contains(src.IP) {
			err := fmt.Errorf("can't send to %v with src %v on interface %v", dst.IP, src.IP, iface)
			trace(p, "%v", err)
			return 0, err
		}
	}
	if src.IP.IsZero() {
		err := fmt.Errorf("no matching address for address family for %v", origSrcIP)
		trace(p, "%v", err)
		return 0, err
	}

	trace(p, "mach=%s src=%s dst=%s -> net=%s", m.Name, src, dst, iface.net.Name)
	return iface.net.write(p, dst, src)
}

func (m *Machine) interfaceForIP(ip netaddr.IP) (*Interface, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, re := range m.routes {
		if re.prefix.Contains(ip) {
			return re.iface, nil
		}
	}
	return nil, fmt.Errorf("no route found to %v", ip)
}

func (m *Machine) hasv6() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.interfaces {
		for _, ip := range f.ips {
			if ip.Is6() {
				return true
			}
		}
	}
	return false
}

func (m *Machine) pickEphemPort() (port uint16, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tries := 0; tries < 500; tries++ {
		port := uint16(rand.Intn(32<<10) + 32<<10)
		if !m.portInUseLocked(port) {
			return port, nil
		}
	}
	return 0, errors.New("failed to find an ephemeral port")
}

func (m *Machine) portInUseLocked(port uint16) bool {
	for ipp := range m.conns4 {
		if ipp.Port == port {
			return true
		}
	}
	for ipp := range m.conns6 {
		if ipp.Port == port {
			return true
		}
	}
	return false
}

func (m *Machine) registerConn4(c *conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ipp.IP.Is6() && c.ipp.IP != v6unspec {
		return fmt.Errorf("registerConn4 got IPv6 %s", c.ipp)
	}
	return registerConn(&m.conns4, c)
}

func (m *Machine) unregisterConn4(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns4, c.ipp)
}

func (m *Machine) registerConn6(c *conn) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ipp.IP.Is4() {
		return fmt.Errorf("registerConn6 got IPv4 %s", c.ipp)
	}
	return registerConn(&m.conns6, c)
}

func (m *Machine) unregisterConn6(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.conns6, c.ipp)
}

func registerConn(conns *map[netaddr.IPPort]*conn, c *conn) error {
	if _, ok := (*conns)[c.ipp]; ok {
		return fmt.Errorf("duplicate conn listening on %v", c.ipp)
	}
	if *conns == nil {
		*conns = map[netaddr.IPPort]*conn{}
	}
	(*conns)[c.ipp] = c
	return nil
}

func (m *Machine) AddNetwork(n *Network) {}

func (m *Machine) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// if udp4, udp6, etc... look at address IP vs unspec
	var (
		fam uint8
		ip  netaddr.IP
	)
	switch network {
	default:
		return nil, fmt.Errorf("unsupported network type %q", network)
	case "udp":
		fam = 0
		ip = v6unspec
	case "udp4":
		fam = 4
		ip = v4unspec
	case "udp6":
		fam = 6
		ip = v6unspec
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host != "" {
		ip, err = netaddr.ParseIP(host)
		if err != nil {
			return nil, err
		}
	}
	porti, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	port := uint16(porti)
	if port == 0 {
		port, err = m.pickEphemPort()
		if err != nil {
			return nil, nil
		}
	}
	ipp := netaddr.IPPort{IP: ip, Port: port}

	c := &conn{
		m:   m,
		fam: fam,
		ipp: ipp,
		in:  make(chan incomingPacket, 100), // arbitrary
	}
	switch c.fam {
	case 0:
		if err := m.registerConn4(c); err != nil {
			return nil, err
		}
		if err := m.registerConn6(c); err != nil {
			m.unregisterConn4(c)
			return nil, err
		}
	case 4:
		if err := m.registerConn4(c); err != nil {
			return nil, err
		}
	case 6:
		if err := m.registerConn6(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// conn is our net.PacketConn implementation
type conn struct {
	m   *Machine
	fam uint8 // 0, 4, or 6
	ipp netaddr.IPPort

	mu           sync.Mutex
	closed       bool
	readDeadline time.Time
	activeReads  map[*activeRead]bool
	in           chan incomingPacket
}

type incomingPacket struct {
	p   []byte
	src netaddr.IPPort
}

type activeRead struct {
	cancel context.CancelFunc
}

// canRead reports whether we can do a read.
func (c *conn) canRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("closed network connection") // sadface: magic string used by other; don't change
	}
	if !c.readDeadline.IsZero() && c.readDeadline.Before(time.Now()) {
		return errors.New("read deadline exceeded")
	}
	return nil
}

func (c *conn) registerActiveRead(ar *activeRead, active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeReads == nil {
		c.activeReads = make(map[*activeRead]bool)
	}
	if active {
		c.activeReads[ar] = true
	} else {
		delete(c.activeReads, ar)
	}
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	switch c.fam {
	case 0:
		c.m.unregisterConn4(c)
		c.m.unregisterConn6(c)
	case 4:
		c.m.unregisterConn4(c)
	case 6:
		c.m.unregisterConn6(c)
	}
	c.breakActiveReadsLocked()
	return nil
}

func (c *conn) breakActiveReadsLocked() {
	for ar := range c.activeReads {
		ar.cancel()
	}
	c.activeReads = nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.ipp.UDPAddr()
}

func (c *conn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ar := &activeRead{cancel: cancel}

	if err := c.canRead(); err != nil {
		return 0, nil, err
	}

	c.registerActiveRead(ar, true)
	defer c.registerActiveRead(ar, false)

	select {
	case pkt := <-c.in:
		n = copy(p, pkt.p)
		trace(pkt.p, "mach=%s src=%s PacketConn.ReadFrom", c.m.Name, pkt.src)
		return n, pkt.src.UDPAddr(), nil
	case <-ctx.Done():
		return 0, nil, context.DeadlineExceeded
	}
}

func (c *conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ipp, err := netaddr.ParseIPPort(addr.String())
	if err != nil {
		return 0, fmt.Errorf("bogus addr %T %q", addr, addr.String())
	}
	return c.m.writePacket(p, ipp, c.ipp)
}

func (c *conn) SetDeadline(t time.Time) error {
	panic("SetWriteDeadline unsupported; TODO when needed")
}
func (c *conn) SetWriteDeadline(t time.Time) error {
	panic("SetWriteDeadline unsupported; TODO when needed")
}
func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if t.After(now) {
		panic("SetReadDeadline in the future not yet supported; TODO?")
	}

	if !t.IsZero() && t.Before(now) {
		c.breakActiveReadsLocked()
	}
	c.readDeadline = t

	return nil
}
