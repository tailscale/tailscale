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
	"bytes"
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

// Packet represents a UDP packet flowing through the virtual network.
type Packet struct {
	Src, Dst netaddr.IPPort
	Payload  []byte

	// Prefix set by various internal methods of natlab, to locate
	// where in the network a trace occured.
	locator string
}

// Equivalent returns true if Src, Dst and Payload are the same in p
// and p2.
func (p *Packet) Equivalent(p2 *Packet) bool {
	return p.Src == p2.Src && p.Dst == p2.Dst && bytes.Equal(p.Payload, p2.Payload)
}

// Clone returns a copy of p that shares nothing with p.
func (p *Packet) Clone() *Packet {
	return &Packet{
		Src:     p.Src,
		Dst:     p.Dst,
		Payload: append([]byte(nil), p.Payload...),
		locator: p.locator,
	}
}

// short returns a short identifier for a packet payload,
// suitable for printing trace information.
func (p *Packet) short() string {
	s := sha256.Sum256(p.Payload)
	payload := base64.RawStdEncoding.EncodeToString(s[:])[:2]

	s = sha256.Sum256([]byte(p.Src.String() + "_" + p.Dst.String()))
	tuple := base64.RawStdEncoding.EncodeToString(s[:])[:2]

	return fmt.Sprintf("%s/%s", payload, tuple)
}

func (p *Packet) Trace(msg string, args ...interface{}) {
	if !traceOn {
		return
	}
	allArgs := []interface{}{p.short(), p.locator, p.Src, p.Dst}
	allArgs = append(allArgs, args...)
	fmt.Fprintf(os.Stderr, "[%s]%s src=%s dst=%s "+msg+"\n", allArgs...)
}

func (p *Packet) setLocator(msg string, args ...interface{}) {
	p.locator = fmt.Sprintf(" "+msg, args...)
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
	if gwIf.net != n {
		panic(fmt.Sprintf("can't set if=%s as net=%s's default gw, if not connected to net", gwIf.name, gwIf.net.Name))
	}
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

func (n *Network) write(p *Packet) (num int, err error) {
	p.setLocator("net=%s", n.Name)

	n.mu.Lock()
	defer n.mu.Unlock()
	iface, ok := n.machine[p.Dst.IP]
	if !ok {
		if n.defaultGW == nil {
			p.Trace("no route to %v", p.Dst.IP)
			return len(p.Payload), nil
		}
		iface = n.defaultGW
	}

	// Pretend it went across the network. Make a copy so nobody
	// can later mess with caller's memory.
	p.Trace("-> mach=%s if=%s", iface.machine.Name, iface.name)
	go iface.machine.deliverIncomingPacket(p, iface)
	return len(p.Payload), nil
}

type Interface struct {
	machine *Machine
	net     *Network
	name    string       // optional
	ips     []netaddr.IP // static; not mutated once created
}

func (f *Interface) Machine() *Machine {
	return f.machine
}

func (f *Interface) Network() *Network {
	return f.net
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

// A PacketHandler can look at packets arriving at, departing, and
// transiting a Machine, and filter or mutate them.
//
// Each method is invoked with a Packet that natlab would like to keep
// processing. Handlers can return that same Packet to allow
// processing to continue; nil to drop the Packet; or a different
// Packet that should be processed instead of the original.
//
// Packets passed to handlers share no state with anything else, and
// are therefore safe to mutate. It's safe to return the original
// packet mutated in-place, or a brand new packet initialized from
// scratch.
//
// Packets mutated by a PacketHandler are processed anew by the
// associated Machine, as if the packet had always been the mutated
// one. For example, if HandleForward is invoked with a Packet, and
// the handler changes the destination IP address to one of the
// Machine's own IPs, the Machine restarts delivery, but this time
// going to a local PacketConn (which in turn will invoke HandleIn,
// since the packet is now destined for local delivery).
type PacketHandler interface {
	// HandleIn processes a packet arriving on iif, whose destination
	// is an IP address owned by the attached Machine. If p is
	// returned unmodified, the Machine will go on to deliver the
	// Packet to the appropriate listening PacketConn, if one exists.
	HandleIn(p *Packet, iif *Interface) *Packet
	// HandleOut processes a packet about to depart on oif from a
	// local PacketConn. If p is returned unmodified, the Machine will
	// transmit the Packet on oif.
	HandleOut(p *Packet, oif *Interface) *Packet
	// HandleForward is called when the Machine wants to forward a
	// packet from iif to oif. If p is returned unmodified, the
	// Machine will transmit the packet on oif.
	HandleForward(p *Packet, iif, oif *Interface) *Packet
}

// A Machine is a representation of an operating system's network
// stack. It has a network routing table and can have multiple
// attached networks. The zero value is valid, but lacks any
// networking capability until Attach is called.
type Machine struct {
	// Name is a pretty name for debugging and packet tracing. It need
	// not be globally unique.
	Name string

	// PacketHandler, if not nil, is a PacketHandler implementation
	// that inspects all packets arriving, departing, or transiting
	// the Machine. See the definition of the PacketHandler interface
	// for semantics.
	//
	// If PacketHandler is nil, the machine allows all inbound
	// traffic, all outbound traffic, and drops forwarded packets.
	PacketHandler PacketHandler

	mu         sync.Mutex
	interfaces []*Interface
	routes     []routeEntry // sorted by longest prefix to shortest

	conns4 map[netaddr.IPPort]*conn // conns that want IPv4 packets
	conns6 map[netaddr.IPPort]*conn // conns that want IPv6 packets
}

func (m *Machine) isLocalIP(ip netaddr.IP) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, intf := range m.interfaces {
		for _, iip := range intf.ips {
			if ip == iip {
				return true
			}
		}
	}
	return false
}

func (m *Machine) deliverIncomingPacket(p *Packet, iface *Interface) {
	p.setLocator("mach=%s if=%s", m.Name, iface.name)

	if m.isLocalIP(p.Dst.IP) {
		m.deliverLocalPacket(p, iface)
	} else {
		m.forwardPacket(p, iface)
	}
}

func (m *Machine) deliverLocalPacket(p *Packet, iface *Interface) {
	// TODO: can't hold lock while handling packet. This is safe as
	// long as you set HandlePacket before traffic starts flowing.
	if m.PacketHandler != nil {
		p2 := m.PacketHandler.HandleIn(p.Clone(), iface)
		if p2 == nil {
			// Packet dropped, nothing left to do.
			return
		}
		if !p.Equivalent(p2) {
			// Restart delivery, this packet might be a forward packet
			// now.
			m.deliverIncomingPacket(p2, iface)
			return
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	conns := m.conns4
	if p.Dst.IP.Is6() {
		conns = m.conns6
	}
	possibleDsts := []netaddr.IPPort{
		p.Dst,
		netaddr.IPPort{IP: v6unspec, Port: p.Dst.Port},
		netaddr.IPPort{IP: v4unspec, Port: p.Dst.Port},
	}
	for _, dest := range possibleDsts {
		c, ok := conns[dest]
		if !ok {
			continue
		}
		select {
		case c.in <- p:
			p.Trace("queued to conn")
		default:
			p.Trace("dropped, queue overflow")
			// Queue overflow. Just drop it.
		}
		return
	}
	p.Trace("dropped, no listening conn")
}

func (m *Machine) forwardPacket(p *Packet, iif *Interface) {
	oif, err := m.interfaceForIP(p.Dst.IP)
	if err != nil {
		p.Trace("%v", err)
		return
	}

	if m.PacketHandler == nil {
		// Forwarding not allowed by default
		p.Trace("drop, forwarding not allowed")
		return
	}
	p2 := m.PacketHandler.HandleForward(p.Clone(), iif, oif)
	if p2 == nil {
		p.Trace("drop")
		// Packet dropped, done.
		return
	}
	if !p.Equivalent(p2) {
		// Packet changed, restart delivery.
		p2.Trace("PacketHandler mutated packet")
		m.deliverIncomingPacket(p2, iif)
		return
	}

	p.Trace("-> net=%s oif=%s", oif.net.Name, oif)
	oif.net.write(p)
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

func (m *Machine) writePacket(p *Packet) (n int, err error) {
	p.setLocator("mach=%s", m.Name)

	iface, err := m.interfaceForIP(p.Dst.IP)
	if err != nil {
		p.Trace("%v", err)
		return 0, err
	}
	origSrcIP := p.Src.IP
	switch {
	case p.Src.IP == v4unspec:
		p.Trace("assigning srcIP=%s", iface.V4())
		p.Src.IP = iface.V4()
	case p.Src.IP == v6unspec:
		// v6unspec in Go means "any src, but match address families"
		if p.Dst.IP.Is6() {
			p.Trace("assigning srcIP=%s", iface.V6())
			p.Src.IP = iface.V6()
		} else if p.Dst.IP.Is4() {
			p.Trace("assigning srcIP=%s", iface.V4())
			p.Src.IP = iface.V4()
		}
	default:
		if !iface.Contains(p.Src.IP) {
			err := fmt.Errorf("can't send to %v with src %v on interface %v", p.Dst.IP, p.Src.IP, iface)
			p.Trace("%v", err)
			return 0, err
		}
	}
	if p.Src.IP.IsZero() {
		err := fmt.Errorf("no matching address for address family for %v", origSrcIP)
		p.Trace("%v", err)
		return 0, err
	}

	if m.PacketHandler != nil {
		p2 := m.PacketHandler.HandleOut(p.Clone(), iface)
		if p2 == nil {
			// Packet dropped, done.
			return len(p.Payload), nil
		}
		if !p.Equivalent(p2) {
			// Restart transmission, src may have changed weirdly
			m.writePacket(p2)
			return
		}
	}

	p.Trace("-> net=%s if=%s", iface.net.Name, iface)
	return iface.net.write(p)
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
		if fam == 0 && (ip != v4unspec && ip != v6unspec) {
			// We got an explicit IP address, need to switch the
			// family to the right one.
			if ip.Is4() {
				fam = 4
			} else {
				fam = 6
			}
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
		in:  make(chan *Packet, 100), // arbitrary
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
	in           chan *Packet
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
		n = copy(p, pkt.Payload)
		pkt.Trace("PacketConn.ReadFrom")
		return n, pkt.Src.UDPAddr(), nil
	case <-ctx.Done():
		return 0, nil, context.DeadlineExceeded
	}
}

func (c *conn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	ipp, err := netaddr.ParseIPPort(addr.String())
	if err != nil {
		return 0, fmt.Errorf("bogus addr %T %q", addr, addr.String())
	}
	pkt := &Packet{
		Src:     c.ipp,
		Dst:     ipp,
		Payload: append([]byte(nil), p...),
	}
	pkt.setLocator("mach=%s", c.m.Name)
	pkt.Trace("PacketConn.WriteTo")
	return c.m.writePacket(pkt)
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
