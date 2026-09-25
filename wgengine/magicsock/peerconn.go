// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/net/batching"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockstats"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
)

// This file implements connected per-peer UDP sockets; see [peerConn].

// peerConnSlotCount is the number of [peerConnSlot]s, and thus the number of
// wireguard-go receive goroutines, reserved for connected per-peer sockets.
// It bounds how many peers can use a [peerConn] at the same time. Peers
// beyond that continue to use the main sockets.
const peerConnSlotCount = 16

// peerConnRetryInterval is the minimum time between attempts to open a
// [peerConn] for a given endpoint.
const peerConnRetryInterval = 5 * time.Second

// peerConnDialTimeout bounds the socket setup in [Conn.newPeerConn]. It
// involves no network round trips, so it should never be hit.
const peerConnDialTimeout = 5 * time.Second

// peerConn is a connected UDP socket dedicated to a single peer's direct
// path.
//
// It shares its local address and port with the main magicsock socket of the
// same address family ([Conn.pconn4] or [Conn.pconn6]) via SO_REUSEPORT and
// is then connected to the peer's current best direct address. The peer sees
// no change in our address, so disco, STUN, and NAT traversal are unaffected.
// The kernel delivers the peer's packets to this socket because an exact
// 4-tuple match wins over the wildcard main socket, and sends from it skip
// the per-datagram route lookup an unconnected socket pays. On Darwin, a
// connected socket is also a prerequisite for batched sends via sendmsg_x.
//
// A peerConn is opened lazily from [endpoint.send] once an endpoint has a
// trusted direct address, and is closed whenever that address changes, on
// any socket error, on rebind, and when the [connBind] closes. The endpoint
// falls back to the main sockets whenever it has no peerConn.
//
// Use is opt-in via TS_DEBUG_MAGICSOCK_CONNECTED_SOCKETS for now.
type peerConn struct {
	c      *Conn
	ep     *endpoint
	addr   netip.AddrPort     // connected remote address
	pconn  nettype.PacketConn // a [batching.Conn] where supported, else a [connectedUDPConn]
	slot   *peerConnSlot      // the slot reading from pconn; nil until assigned
	closed atomic.Bool
}

// writeWireGuardBatch writes buffs, each starting at offset, to the connected
// peer. It mirrors [RebindingUDPConn.WriteWireGuardBatchTo] minus Geneve
// encapsulation, which peer relay paths use and a peerConn never carries.
func (pc *peerConn) writeWireGuardBatch(buffs [][]byte, offset int) error {
	if b, ok := pc.pconn.(batching.Conn); ok {
		return b.WriteBatchTo(buffs, pc.addr, packet.GeneveHeader{}, offset)
	}
	for _, buf := range buffs {
		if _, err := pc.pconn.WriteToUDPAddrPort(buf[offset:], pc.addr); err != nil {
			return err
		}
	}
	return nil
}

// readBatch reads packets from the connected peer into slab, describing them
// in pkts. It returns the number of packets read.
func (pc *peerConn) readBatch(slab []byte, pkts []batching.ReceivedPacket) (int, error) {
	if b, ok := pc.pconn.(batching.Conn); ok {
		return b.ReadBatch(slab, pkts)
	}
	n, ap, err := pc.pconn.ReadFromUDPAddrPort(slab)
	if err != nil {
		return 0, err
	}
	pkts[0] = batching.ReceivedPacket{Size: n, Source: netaddr.Unmap(ap)}
	return 1, nil
}

// close closes the socket and releases pc's slot, if any. It is safe to call
// more than once and from any goroutine. It does not touch pc.ep, which the
// caller detaches under [endpoint.mu] as appropriate.
func (pc *peerConn) close(why string) {
	if !pc.closed.CompareAndSwap(false, true) {
		return
	}
	pc.pconn.Close()
	if s := pc.slot; s != nil {
		s.mu.Lock()
		if s.cur == pc {
			s.cur = nil
		}
		s.mu.Unlock()
	}
	metricPeerConnClosed.Add(1)
	pc.c.logf("[v1] magicsock: peerconn: closed %v for %v: %s", pc.addr, pc.ep.publicKey.ShortString(), why)
}

// connectedUDPConn adapts a connected [*net.UDPConn] to [nettype.PacketConn].
// Go's [net.UDPConn.WriteToUDPAddrPort] refuses connected sockets, so writes
// go through [net.UDPConn.Write] instead and the destination is ignored.
type connectedUDPConn struct {
	*net.UDPConn
}

func (c connectedUDPConn) WriteToUDPAddrPort(b []byte, _ netip.AddrPort) (int, error) {
	return c.Write(b)
}

// batchReader is the read side shared by [RebindingUDPConn] and
// [peerConnSlot], from which [Conn.mkReceiveFunc] builds a
// wireguard-go receive function.
type batchReader interface {
	ReadBatch(slab []byte, pkts []batching.ReceivedPacket) (int, error)
}

// peerConnSlot is one of a fixed number of wireguard-go receive functions
// reserved for peerConns.
//
// wireguard-go fixes its set of receive functions when the bind is opened,
// so the slots exist from the start and each one blocks until a [peerConn] is
// assigned to it. A slot reads from its peerConn until the socket errors or
// is closed, then releases it and waits for the next assignment. Errors are
// never returned to wireguard-go (which would stop the receive goroutine
// for good) except [net.ErrClosed] when the bind closes.
type peerConnSlot struct {
	done <-chan struct{} // closed when the connBind that created the slot closes
	wake chan struct{}   // 1-buffered; signaled on assignment

	mu  sync.Mutex
	cur *peerConn
}

// ReadBatch implements [batchReader].
func (s *peerConnSlot) ReadBatch(slab []byte, pkts []batching.ReceivedPacket) (int, error) {
	for {
		s.mu.Lock()
		pc := s.cur
		s.mu.Unlock()
		if pc == nil {
			select {
			case <-s.wake:
				continue
			case <-s.done:
				return 0, net.ErrClosed
			}
		}
		n, err := pc.readBatch(slab, pkts)
		if err == nil {
			metricRecvPeerConn.Add(int64(n))
			return n, nil
		}
		if neterror.PacketWasTruncated(err) {
			continue
		}
		// Anything else, including ECONNREFUSED from an ICMP error that
		// the kernel reports only on connected sockets, ends this
		// peerConn. The endpoint falls back to the main socket and may
		// open a new one later.
		if !pc.closed.Load() {
			pc.close(fmt.Sprintf("read error: %v", err))
		}
		pc.ep.detachPeerConn(pc)
	}
}

// peerConnState is the [Conn]-wide state for peerConns.
type peerConnState struct {
	// enabled is whether peerConns may be used at all. It is set once in
	// [NewConn] and requires both the TS_DEBUG_MAGICSOCK_CONNECTED_SOCKETS
	// envknob and a passing [peerConnSupported] self-test.
	enabled bool

	// mu guards the fields below. It is a leaf lock with respect to
	// [Conn.mu] and [endpoint.mu]: nothing may be acquired while holding it.
	mu    sync.Mutex
	slots []*peerConnSlot // nil while the connBind is closed
	done  chan struct{}   // closed by closePeerConnSlots; nil while closed
	// rebindGen counts rebinds of the main sockets. A peerConn opened
	// against one generation's port must not be installed in a later one.
	rebindGen uint64
}

// wrapReusePort wraps lc.Control so that sockets it creates have SO_REUSEPORT
// set before bind, which the kernel requires of both the main socket and any
// [peerConn] sharing its port.
func wrapReusePort(lc *net.ListenConfig) {
	inner := lc.Control
	lc.Control = func(network, address string, rc syscall.RawConn) error {
		if err := setReusePort(rc); err != nil {
			return err
		}
		if inner != nil {
			return inner(network, address, rc)
		}
		return nil
	}
}

// openPeerConnSlots creates the peerConn slots for a newly opened [connBind]
// and returns their wireguard-go receive functions. It returns nil if
// peerConns are disabled.
func (c *Conn) openPeerConnSlots() []conn.ReceiveFunc {
	if !c.peerConns.enabled {
		return nil
	}
	c.peerConns.mu.Lock()
	defer c.peerConns.mu.Unlock()
	done := make(chan struct{})
	c.peerConns.done = done
	c.peerConns.slots = make([]*peerConnSlot, 0, peerConnSlotCount)
	fns := make([]conn.ReceiveFunc, 0, peerConnSlotCount)
	for range peerConnSlotCount {
		s := &peerConnSlot{
			done: done,
			wake: make(chan struct{}, 1),
		}
		c.peerConns.slots = append(c.peerConns.slots, s)
		fns = append(fns, c.mkReceiveFunc(s, nil, nil))
	}
	return fns
}

// closeAllPeerConns closes all open peerConns, leaving their slots free for
// new ones. It is called when the main sockets rebind.
func (c *Conn) closeAllPeerConns(why string) {
	c.peerConns.mu.Lock()
	c.peerConns.rebindGen++
	pcs := c.openPeerConnsLocked()
	c.peerConns.mu.Unlock()
	for _, pc := range pcs {
		pc.close(why)
		pc.ep.detachPeerConn(pc)
	}
}

// openPeerConnsLocked returns the peerConns currently assigned to slots.
//
// c.peerConns.mu must be held.
func (c *Conn) openPeerConnsLocked() []*peerConn {
	var pcs []*peerConn
	for _, s := range c.peerConns.slots {
		s.mu.Lock()
		if s.cur != nil {
			pcs = append(pcs, s.cur)
		}
		s.mu.Unlock()
	}
	return pcs
}

// closePeerConnSlots closes all open peerConns and unblocks their slots'
// receive functions, which then return [net.ErrClosed] to wireguard-go. It
// is called when the [connBind] closes. It is a no-op if peerConns are
// disabled or the slots are already closed.
func (c *Conn) closePeerConnSlots(why string) {
	c.peerConns.mu.Lock()
	pcs := c.openPeerConnsLocked()
	c.peerConns.slots = nil
	if c.peerConns.done != nil {
		close(c.peerConns.done)
		c.peerConns.done = nil
	}
	c.peerConns.mu.Unlock()
	for _, pc := range pcs {
		pc.close(why)
		pc.ep.detachPeerConn(pc)
	}
}

// peerConnRebindGen returns the current rebind generation, to be passed to
// [Conn.assignPeerConnSlot] by whoever opens a peerConn against the current
// main sockets.
func (c *Conn) peerConnRebindGen() uint64 {
	c.peerConns.mu.Lock()
	defer c.peerConns.mu.Unlock()
	return c.peerConns.rebindGen
}

// assignPeerConnSlot gives pc a free slot, returning false if none is free,
// the bind is closed, or the main sockets have rebound since gen.
func (c *Conn) assignPeerConnSlot(pc *peerConn, gen uint64) bool {
	c.peerConns.mu.Lock()
	defer c.peerConns.mu.Unlock()
	if gen != c.peerConns.rebindGen {
		return false
	}
	for _, s := range c.peerConns.slots {
		s.mu.Lock()
		if s.cur != nil {
			s.mu.Unlock()
			continue
		}
		s.cur = pc
		pc.slot = s
		s.mu.Unlock()
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return true
	}
	return false
}

var errPeerConnUnbound = errors.New("main socket not bound")

// newPeerConn opens a connected socket to addr for de, sharing the local
// address and port of the main socket of addr's address family. The returned
// peerConn has no slot yet. It also returns the rebind generation the socket
// was opened against, for [Conn.assignPeerConnSlot].
func (c *Conn) newPeerConn(de *endpoint, addr netip.AddrPort) (_ *peerConn, gen uint64, _ error) {
	gen = c.peerConnRebindGen()
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	network, ruc, label := "udp4", &c.pconn4, sockstats.LabelMagicsockConnUDP4
	if addr.Addr().Is6() {
		network, ruc, label = "udp6", &c.pconn6, sockstats.LabelMagicsockConnUDP6
	}
	laddr := ruc.LocalAddr()
	if laddr == nil || laddr.Port == 0 {
		return nil, 0, errPeerConnUnbound
	}
	d := &net.Dialer{LocalAddr: laddr}
	if c.testOnlyPacketListener == nil {
		// Set the same interface binding and/or fwmark as the main
		// socket so sends can't loop back into the tunnel. Tests bind
		// to loopback and may lack the privileges for this.
		netns.FromDialer(c.logf, c.netMon, d)
	}
	inner := d.Control
	d.Control = func(network, address string, rc syscall.RawConn) error {
		if err := setReusePort(rc); err != nil {
			return err
		}
		if inner != nil {
			return inner(network, address, rc)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), peerConnDialTimeout)
	defer cancel()
	ctx = sockstats.WithSockStats(ctx, label, c.logf)
	nc, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return nil, 0, err
	}
	uc, ok := nc.(*net.UDPConn)
	if !ok {
		nc.Close()
		return nil, 0, fmt.Errorf("unexpected conn type %T", nc)
	}
	trySetUDPSocketOptions(uc, c.logf)
	if err := c.setDontFragmentOn(uc, network, c.peerMTUEnabled.Load()); err != nil {
		c.logf("magicsock: peerconn: setting DF bit on %v: %v", addr, err)
	}
	var pconn nettype.PacketConn = connectedUDPConn{uc}
	if up := batching.TryUpgradeConnectedToConn(uc, network, c.controlKnobs); up != nettype.PacketConn(uc) {
		pconn = up
	}
	return &peerConn{
		c:     c,
		ep:    de,
		addr:  addr,
		pconn: pconn,
	}, gen, nil
}

// peerConnForSendLocked returns the [peerConn] to use for sending to udpAddr,
// or nil to use the main sockets. If de has a trusted direct address but no
// matching peerConn, it starts opening one in the background, at most once
// per [peerConnRetryInterval].
//
// de.mu must be held.
func (de *endpoint) peerConnForSendLocked(udpAddr epAddr, now mono.Time) *peerConn {
	if pc := de.peerConn; pc != nil {
		if pc.addr == udpAddr.ap && !udpAddr.vni.IsSet() && !pc.closed.Load() {
			return pc
		}
		// The best address moved, or the slot closed it.
		de.closePeerConnLocked("best address changed")
	}
	if !de.c.peerConns.enabled || !udpAddr.isDirect() || now.After(de.trustBestAddrUntil) {
		return nil
	}
	if de.peerConnOpening || now.Sub(de.peerConnLastAttempt) < peerConnRetryInterval {
		return nil
	}
	de.peerConnLastAttempt = now
	de.peerConnOpening = true
	go de.openPeerConn(udpAddr.ap)
	return nil
}

// openPeerConn opens a peerConn to addr and, if de's best address is still
// addr by the time it's ready, installs it. It runs in its own goroutine.
func (de *endpoint) openPeerConn(addr netip.AddrPort) {
	pc, gen, err := de.c.newPeerConn(de, addr)

	de.mu.Lock()
	defer de.mu.Unlock()
	de.peerConnOpening = false
	if err != nil {
		metricPeerConnOpenError.Add(1)
		de.c.logf("magicsock: peerconn: opening %v for %v: %v", addr, de.publicKey.ShortString(), err)
		return
	}
	if de.bestAddr.epAddr != (epAddr{ap: addr}) || de.peerConn != nil || de.c.closing.Load() {
		pc.close("best address changed while opening")
		return
	}
	if !de.c.assignPeerConnSlot(pc, gen) {
		metricPeerConnNoSlot.Add(1)
		pc.close("no free slot or rebound")
		return
	}
	metricPeerConnOpened.Add(1)
	de.peerConn = pc
	de.debugUpdates.Add(EndpointChange{
		When: time.Now(),
		What: "peerConn-open",
		To:   addr,
	})
	de.c.logf("[v1] magicsock: peerconn: opened %v for %v via %T", addr, de.publicKey.ShortString(), pc.pconn)
}

// closePeerConnLocked closes and detaches de's peerConn, if any.
//
// de.mu must be held.
func (de *endpoint) closePeerConnLocked(why string) {
	if pc := de.peerConn; pc != nil {
		de.peerConn = nil
		pc.close(why)
	}
}

// detachPeerConn clears de.peerConn if it is still pc. It is called by
// whoever closed pc without holding de.mu.
func (de *endpoint) detachPeerConn(pc *peerConn) {
	de.mu.Lock()
	defer de.mu.Unlock()
	if de.peerConn == pc {
		de.peerConn = nil
	}
}

var (
	metricPeerConnOpened    = clientmetric.NewCounter("magicsock_peerconn_opened")
	metricPeerConnOpenError = clientmetric.NewCounter("magicsock_peerconn_open_error")
	metricPeerConnNoSlot    = clientmetric.NewCounter("magicsock_peerconn_no_slot")
	metricPeerConnClosed    = clientmetric.NewCounter("magicsock_peerconn_closed")
	metricPeerConnSendError = clientmetric.NewCounter("magicsock_peerconn_send_error")
	metricSendPeerConn      = clientmetric.NewCounter("magicsock_send_peerconn") // packets sent via a peerConn
	metricRecvPeerConn      = clientmetric.NewCounter("magicsock_recv_peerconn") // packets received via a peerConn
)
