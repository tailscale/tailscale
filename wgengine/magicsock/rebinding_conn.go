// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"tailscale.com/control/controlknobs"
	"tailscale.com/net/batching"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockopts"
	"tailscale.com/syncs"
	"tailscale.com/types/nettype"
)

// socketGroup contains sockets sharing one port.
type socketGroup struct {
	// conns hold the group members.
	// Consumers expect at least one, and will panic otherwise.
	conns []nettype.PacketConn

	// bound tracks the number of live conns to manage their lifecycle.
	//
	// Subject to OS capabilities and state, conns[bound:] connections may
	// be backed by a [blockForeverConn].
	bound int
}

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	// groupAtomic is a pointer to the value stored in group, but doesn't
	// require acquiring mu. It's used for reads/writes and only upon failure
	// do the reads/writes then check pconn sockets (after acquiring mu) to see if
	// there's been a rebind meanwhile.
	// group isn't really needed, but makes some of the code simpler
	// to keep it distinct.
	// Neither is expected to be less than one member, sockets are bound on creation.
	groupAtomic atomic.Pointer[socketGroup]

	mu    syncs.Mutex // held while changing group (and groupAtomic)
	group socketGroup
	port  uint16
}

// setConnLocked sets the provided [nettype.PacketConn]s. It should be called only
// after acquiring RebindingUDPConn.mu. It upgrades the provided
// [nettype.PacketConn]s to [batching.Conn]s when appropriate. This upgrade is
// intentionally pushed closest to where read/write ops occur in order to avoid
// disrupting surrounding code that assumes nettype.PacketConn is a
// *net.UDPConn. knobs may be nil.
//
// If less than n conns are provided, ps is padded out with [blockForeverConn]s.
func (c *RebindingUDPConn) setConnLocked(ps []nettype.PacketConn, n int, network string, knobs *controlknobs.Knobs) {
	if hasUDPTransport {
		for i := range ps {
			ps[i] = batching.TryUpgradeToConn(ps[i], network, "magicsock_udp_rxq_overflows", knobs)
		}
	}
	g := socketGroup{conns: ps, bound: len(ps)}
	for len(g.conns) < n {
		g.conns = append(g.conns, newBlockForeverConn())
	}
	c.group = g
	c.groupAtomic.Store(&g)
	c.port = uint16(c.localAddrLocked().Port)
}

// currentConn returns c's current socket i, acquiring c.mu in the process.
func (c *RebindingUDPConn) currentConn(i int) nettype.PacketConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.group.conns[i]
}

// connAt returns socket i without acquiring c.mu.
func (c *RebindingUDPConn) connAt(i int) nettype.PacketConn {
	return c.groupAtomic.Load().conns[i]
}

// controlEach applies fn on the currently bound sockets.
func (c *RebindingUDPConn) controlEach(fn func(fd uintptr) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sockopts.ControlEach(c.group.conns[:c.group.bound], fn)
}

// sendConn returns the socket that flow's packets leave from, and its index.
// A blocking conn is returned if no conns are bound.
func (c *RebindingUDPConn) sendConn(flow int) (int, nettype.PacketConn) {
	g := c.groupAtomic.Load()
	if g.bound <= 1 {
		return 0, g.conns[0]
	}
	i := int(uint(flow) % uint(g.bound))
	return i, g.conns[i]
}

func (c *RebindingUDPConn) readFromWithInitPconn(i int, pconn nettype.PacketConn, b []byte) (int, netip.AddrPort, error) {
	for {
		n, addr, err := pconn.ReadFromUDPAddrPort(b)
		if err != nil {
			if cur := c.currentConn(i); cur != pconn {
				pconn = cur
				continue
			}
		}
		return n, addr, err
	}
}

// WriteWireGuardBatchTo writes buffs to addr. It serves primarily as an alias
// for [batching.Conn.WriteBatchTo], with fallback to single packet operations
// if c.pconn is not a [batching.Conn].
//
// Flow pins the write to one of c's sockets; see [Conn.SendTo].
//
// WriteWireGuardBatchTo assumes buffs are WireGuard packets, which is notable
// for Geneve encapsulation: Geneve protocol is set to [packet.GeneveProtocolWireGuard],
// and the control bit is left unset.
func (c *RebindingUDPConn) WriteWireGuardBatchTo(flow int, buffs [][]byte, addr epAddr, offset int) error {
	if offset != packet.GeneveFixedHeaderLength {
		return fmt.Errorf("RebindingUDPConn.WriteWireGuardBatchTo: [unexpected] offset (%d) != Geneve header length (%d)", offset, packet.GeneveFixedHeaderLength)
	}
	gh := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
		VNI:      addr.vni,
	}
	for {
		i, pconn := c.sendConn(flow)
		b, ok := pconn.(batching.Conn)
		if !ok {
			for _, buf := range buffs {
				if gh.VNI.IsSet() {
					gh.Encode(buf)
				} else {
					buf = buf[offset:]
				}
				_, err := c.writeToUDPAddrPortWithInitPconn(i, pconn, buf, addr.ap)
				if err != nil {
					return err
				}
			}
			return nil
		}
		err := b.WriteBatchTo(buffs, addr.ap, gh, offset)
		if err != nil {
			if pconn != c.currentConn(i) {
				continue
			}
			return err
		}
		return err
	}
}

// ReadBatch is an alias for [batching.Conn.ReadBatch] with fallback to single
// packet operations if c.pconn is not a [batching.Conn].
// It reads from socket i.
func (c *RebindingUDPConn) ReadBatch(i int, slab []byte, batchingPackets []batching.ReceivedPacket) (int, error) {
	for {
		pconn := c.connAt(i)
		b, ok := pconn.(batching.Conn)
		if !ok {
			n, ap, err := c.readFromWithInitPconn(i, pconn, slab)
			if err == nil {
				batchingPackets[0].Offset = 0
				batchingPackets[0].Size = n
				batchingPackets[0].Source = netaddr.Unmap(ap)
				return 1, nil
			}
			return 0, err
		}
		n, err := b.ReadBatch(slab, batchingPackets)
		if err != nil && pconn != c.currentConn(i) {
			continue
		}
		return n, err
	}
}

func (c *RebindingUDPConn) Port() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.port
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localAddrLocked()
}

func (c *RebindingUDPConn) localAddrLocked() *net.UDPAddr {
	return c.group.conns[0].LocalAddr().(*net.UDPAddr)
}

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *RebindingUDPConn) closeLocked() error {
	c.port = 0
	var errs []error
	for sock, pconn := range c.group.conns {
		if err := pconn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("socket %d (%v): %w", sock, pconn.LocalAddr(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *RebindingUDPConn) writeToUDPAddrPortWithInitPconn(i int, pconn nettype.PacketConn, b []byte, addr netip.AddrPort) (int, error) {
	for {
		n, err := pconn.WriteToUDPAddrPort(b, addr)
		if err != nil {
			if cur := c.currentConn(i); cur != pconn {
				pconn = cur
				continue
			}
		}
		return n, err
	}
}

// WriteToUDPAddrPort writes b to addr from c's first socket.
// Intended for the locally initiated traffic.
func (c *RebindingUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.writeToUDPAddrPortWithInitPconn(0, c.connAt(0), b, addr)
}
