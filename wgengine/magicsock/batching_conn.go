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
	"time"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/neterror"
	"tailscale.com/types/nettype"
)

// xnetBatchReaderWriter defines the batching i/o methods of
// golang.org/x/net/ipv4.PacketConn (and ipv6.PacketConn).
// TODO(jwhited): This should eventually be replaced with the standard library
// implementation of https://github.com/golang/go/issues/45886
type xnetBatchReaderWriter interface {
	xnetBatchReader
	xnetBatchWriter
}

type xnetBatchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type xnetBatchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

// batchingUDPConn is a UDP socket that provides batched i/o.
type batchingUDPConn struct {
	pc                    nettype.PacketConn
	xpc                   xnetBatchReaderWriter
	rxOffload             bool                                  // supports UDP GRO or similar
	txOffload             atomic.Bool                           // supports UDP GSO or similar
	setGSOSizeInControl   func(control *[]byte, gsoSize uint16) // typically setGSOSizeInControl(); swappable for testing
	getGSOSizeFromControl func(control []byte) (int, error)     // typically getGSOSizeFromControl(); swappable for testing
	sendBatchPool         sync.Pool
}

func (c *batchingUDPConn) ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	if c.rxOffload {
		// UDP_GRO is opt-in on Linux via setsockopt(). Once enabled you may
		// receive a "monster datagram" from any read call. The ReadFrom() API
		// does not support passing the GSO size and is unsafe to use in such a
		// case. Other platforms may vary in behavior, but we go with the most
		// conservative approach to prevent this from becoming a footgun in the
		// future.
		return 0, netip.AddrPort{}, errors.New("rx UDP offload is enabled on this socket, single packet reads are unavailable")
	}
	return c.pc.ReadFromUDPAddrPort(p)
}

func (c *batchingUDPConn) SetDeadline(t time.Time) error {
	return c.pc.SetDeadline(t)
}

func (c *batchingUDPConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

func (c *batchingUDPConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

const (
	// This was initially established for Linux, but may split out to
	// GOOS-specific values later. It originates as UDP_MAX_SEGMENTS in the
	// kernel's TX path, and UDP_GRO_CNT_MAX for RX.
	udpSegmentMaxDatagrams = 64
)

const (
	// Exceeding these values results in EMSGSIZE.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8
)

// coalesceMessages iterates msgs, coalescing them where possible while
// maintaining datagram order. All msgs have their Addr field set to addr.
func (c *batchingUDPConn) coalesceMessages(addr *net.UDPAddr, buffs [][]byte, msgs []ipv6.Message) int {
	var (
		base     = -1 // index of msg we are currently coalescing into
		gsoSize  int  // segmentation size of msgs[base]
		dgramCnt int  // number of dgrams coalesced into msgs[base]
		endBatch bool // tracking flag to start a new batch on next iteration of buffs
	)
	maxPayloadLen := maxIPv4PayloadLen
	if addr.IP.To4() == nil {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buff := range buffs {
		if i > 0 {
			msgLen := len(buff)
			baseLenBefore := len(msgs[base].Buffers[0])
			freeBaseCap := cap(msgs[base].Buffers[0]) - baseLenBefore
			if msgLen+baseLenBefore <= maxPayloadLen &&
				msgLen <= gsoSize &&
				msgLen <= freeBaseCap &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				msgs[base].Buffers[0] = append(msgs[base].Buffers[0], make([]byte, msgLen)...)
				copy(msgs[base].Buffers[0][baseLenBefore:], buff)
				if i == len(buffs)-1 {
					c.setGSOSizeInControl(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			c.setGSOSizeInControl(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buff)
		msgs[base].OOB = msgs[base].OOB[:0]
		msgs[base].Buffers[0] = buff
		msgs[base].Addr = addr
		dgramCnt = 1
	}
	return base + 1
}

type sendBatch struct {
	msgs []ipv6.Message
	ua   *net.UDPAddr
}

func (c *batchingUDPConn) getSendBatch() *sendBatch {
	batch := c.sendBatchPool.Get().(*sendBatch)
	return batch
}

func (c *batchingUDPConn) putSendBatch(batch *sendBatch) {
	for i := range batch.msgs {
		batch.msgs[i] = ipv6.Message{Buffers: batch.msgs[i].Buffers, OOB: batch.msgs[i].OOB}
	}
	c.sendBatchPool.Put(batch)
}

func (c *batchingUDPConn) WriteBatchTo(buffs [][]byte, addr netip.AddrPort) error {
	batch := c.getSendBatch()
	defer c.putSendBatch(batch)
	if addr.Addr().Is6() {
		as16 := addr.Addr().As16()
		copy(batch.ua.IP, as16[:])
		batch.ua.IP = batch.ua.IP[:16]
	} else {
		as4 := addr.Addr().As4()
		copy(batch.ua.IP, as4[:])
		batch.ua.IP = batch.ua.IP[:4]
	}
	batch.ua.Port = int(addr.Port())
	var (
		n       int
		retried bool
	)
retry:
	if c.txOffload.Load() {
		n = c.coalesceMessages(batch.ua, buffs, batch.msgs)
	} else {
		for i := range buffs {
			batch.msgs[i].Buffers[0] = buffs[i]
			batch.msgs[i].Addr = batch.ua
			batch.msgs[i].OOB = batch.msgs[i].OOB[:0]
		}
		n = len(buffs)
	}

	err := c.writeBatch(batch.msgs[:n])
	if err != nil && c.txOffload.Load() && neterror.ShouldDisableUDPGSO(err) {
		c.txOffload.Store(false)
		retried = true
		goto retry
	}
	if retried {
		return neterror.ErrUDPGSODisabled{OnLaddr: c.pc.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (c *batchingUDPConn) SyscallConn() (syscall.RawConn, error) {
	sc, ok := c.pc.(syscall.Conn)
	if !ok {
		return nil, errUnsupportedConnType
	}
	return sc.SyscallConn()
}
