// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/nettype"
)

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	// pconnAtomic is a pointer to the value stored in pconn, but doesn't
	// require acquiring mu. It's used for reads/writes and only upon failure
	// do the reads/writes then check pconn (after acquiring mu) to see if
	// there's been a rebind meanwhile.
	// pconn isn't really needed, but makes some of the code simpler
	// to keep it distinct.
	// Neither is expected to be nil, sockets are bound on creation.
	pconnAtomic atomic.Pointer[nettype.PacketConn]

	mu    sync.Mutex // held while changing pconn (and pconnAtomic)
	pconn nettype.PacketConn
	port  uint16
}

// setConnLocked sets the provided nettype.PacketConn. It should be called only
// after acquiring RebindingUDPConn.mu. It upgrades the provided
// nettype.PacketConn to a *batchingUDPConn when appropriate. This upgrade
// is intentionally pushed closest to where read/write ops occur in order to
// avoid disrupting surrounding code that assumes nettype.PacketConn is a
// *net.UDPConn.
func (c *RebindingUDPConn) setConnLocked(p nettype.PacketConn, network string, batchSize int) {
	upc := tryUpgradeToBatchingUDPConn(p, network, batchSize)
	c.pconn = upc
	c.pconnAtomic.Store(&upc)
	c.port = uint16(c.localAddrLocked().Port)
}

// currentConn returns c's current pconn, acquiring c.mu in the process.
func (c *RebindingUDPConn) currentConn() nettype.PacketConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn
}

func (c *RebindingUDPConn) readFromWithInitPconn(pconn nettype.PacketConn, b []byte) (int, netip.AddrPort, error) {
	for {
		n, addr, err := pconn.ReadFromUDPAddrPort(b)
		if err != nil && pconn != c.currentConn() {
			pconn = *c.pconnAtomic.Load()
			continue
		}
		return n, addr, err
	}
}

// ReadFromUDPAddrPort reads a packet from c into b.
// It returns the number of bytes copied and the source address.
func (c *RebindingUDPConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return c.readFromWithInitPconn(*c.pconnAtomic.Load(), b)
}

// WriteBatchTo writes buffs to addr.
func (c *RebindingUDPConn) WriteBatchTo(buffs [][]byte, addr netip.AddrPort) error {
	for {
		pconn := *c.pconnAtomic.Load()
		b, ok := pconn.(*batchingUDPConn)
		if !ok {
			for _, buf := range buffs {
				_, err := c.writeToUDPAddrPortWithInitPconn(pconn, buf, addr)
				if err != nil {
					return err
				}
			}
			return nil
		}
		err := b.WriteBatchTo(buffs, addr)
		if err != nil {
			if pconn != c.currentConn() {
				continue
			}
			return err
		}
		return err
	}
}

// ReadBatch reads messages from c into msgs. It returns the number of messages
// the caller should evaluate for nonzero len, as a zero len message may fall
// on either side of a nonzero.
func (c *RebindingUDPConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	for {
		pconn := *c.pconnAtomic.Load()
		b, ok := pconn.(*batchingUDPConn)
		if !ok {
			n, ap, err := c.readFromWithInitPconn(pconn, msgs[0].Buffers[0])
			if err == nil {
				msgs[0].N = n
				msgs[0].Addr = net.UDPAddrFromAddrPort(netaddr.Unmap(ap))
				return 1, nil
			}
			return 0, err
		}
		n, err := b.ReadBatch(msgs, flags)
		if err != nil && pconn != c.currentConn() {
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
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

// errNilPConn is returned by RebindingUDPConn.Close when there is no current pconn.
// It is for internal use only and should not be returned to users.
var errNilPConn = errors.New("nil pconn")

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *RebindingUDPConn) closeLocked() error {
	if c.pconn == nil {
		return errNilPConn
	}
	c.port = 0
	return c.pconn.Close()
}

func (c *RebindingUDPConn) writeToUDPAddrPortWithInitPconn(pconn nettype.PacketConn, b []byte, addr netip.AddrPort) (int, error) {
	for {
		n, err := pconn.WriteToUDPAddrPort(b, addr)
		if err != nil && pconn != c.currentConn() {
			pconn = *c.pconnAtomic.Load()
			continue
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.writeToUDPAddrPortWithInitPconn(*c.pconnAtomic.Load(), b, addr)
}

func (c *RebindingUDPConn) SyscallConn() (syscall.RawConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sc, ok := c.pconn.(syscall.Conn)
	if !ok {
		return nil, errUnsupportedConnType
	}
	return sc.SyscallConn()
}
