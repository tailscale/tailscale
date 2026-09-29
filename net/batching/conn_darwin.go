// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package batching

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/net/msgx"
	"tailscale.com/net/packet"
	"tailscale.com/types/nettype"
)

// darwinReadSlotSize is the slab space given to each datagram in
// [darwinBatchingConn.ReadBatch]. Datagrams larger than this are truncated,
// and since macOS 26 the kernel does so silently, so it must exceed the
// largest datagram a peer might send, including on jumbo frame networks.
// With wireguard-go's 128 KiB batching slab this allows 8 datagrams per
// recvmsg_x call.
const darwinReadSlotSize = 1<<14 - 1

// darwinBatchingConn is a [Conn] for Darwin built on the kernel's recvmsg_x
// and sendmsg_x system calls, via [msgx].
//
// Reads are batched on any socket. Writes are batched only on a connected
// socket, since sendmsg_x takes no per-message destination; on an
// unconnected socket WriteBatchTo falls back to one sendto(2) per datagram.
type darwinBatchingConn struct {
	pc        *net.UDPConn
	rc        syscall.RawConn
	connected bool

	// readOpMu guards msgs. ReadBatch is not called concurrently in
	// practice, but the guard keeps that from being a caller obligation.
	readOpMu sync.Mutex
	msgs     [msgx.MaxBatch]msgx.Message

	payloadsPool sync.Pool // of *[][]byte with cap MaximumWriteBatchSize
}

var errNoSingleReads = errors.New("batching.Conn does not support single packet reads; use ReadBatch")

// ReadFromUDPAddrPort implements [Conn]; it always returns an error.
func (c *darwinBatchingConn) ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	return 0, netip.AddrPort{}, errNoSingleReads
}

// ReadBatch implements [Conn].
func (c *darwinBatchingConn) ReadBatch(slab []byte, packets []ReceivedPacket) (n int, err error) {
	c.readOpMu.Lock()
	defer c.readOpMu.Unlock()
	maxMsgs := min(len(slab)/darwinReadSlotSize, len(packets), len(c.msgs))
	if maxMsgs == 0 {
		return 0, fmt.Errorf("ReadBatch: slab of %d bytes and %d packets too small", len(slab), len(packets))
	}
	msgs := c.msgs[:maxMsgs]
	for i := range msgs {
		msgs[i] = msgx.Message{Payload: slab[i*darwinReadSlotSize : (i+1)*darwinReadSlotSize]}
	}
	n, err = msgx.Recv(c.rc, msgs)
	if err != nil {
		return 0, err
	}
	for i, m := range msgs[:n] {
		packets[i] = ReceivedPacket{
			Offset: i * darwinReadSlotSize,
			Size:   m.N,
			Source: m.Addr,
		}
		if m.Flags&syscall.MSG_TRUNC != 0 {
			// Too big for its slot; drop it. Callers skip zero-size packets.
			packets[i].Size = 0
		}
	}
	return n, nil
}

// WriteBatchTo implements [Conn].
func (c *darwinBatchingConn) WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error {
	if len(buffs) > MaximumWriteBatchSize {
		return fmt.Errorf("WriteBatchTo: %d buffs > MaximumWriteBatchSize (%d)", len(buffs), MaximumWriteBatchSize)
	}
	vniIsSet := geneve.VNI.IsSet()
	if vniIsSet {
		if offset != packet.GeneveFixedHeaderLength {
			return fmt.Errorf("WriteBatchTo: offset (%d) != Geneve header length (%d)", offset, packet.GeneveFixedHeaderLength)
		}
		offset = 0
	}
	if !c.connected {
		for _, buf := range buffs {
			if vniIsSet {
				geneve.Encode(buf)
			}
			if _, err := c.pc.WriteToUDPAddrPort(buf[offset:], addr); err != nil {
				return err
			}
		}
		return nil
	}
	pp, _ := c.payloadsPool.Get().(*[][]byte)
	if pp == nil {
		pp = new([][]byte)
		*pp = make([][]byte, 0, MaximumWriteBatchSize)
	}
	payloads := (*pp)[:0]
	defer func() {
		clear(payloads[:cap(payloads)])
		*pp = payloads[:0]
		c.payloadsPool.Put(pp)
	}()
	for _, buf := range buffs {
		if vniIsSet {
			geneve.Encode(buf)
		}
		payloads = append(payloads, buf[offset:])
	}
	for rem := payloads; len(rem) > 0; {
		n, err := msgx.Send(c.rc, rem)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		rem = rem[n:]
	}
	return nil
}

// WriteToUDPAddrPort implements [nettype.PacketConn]. On a connected socket
// addr is ignored, as the kernel refuses a destination there.
func (c *darwinBatchingConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c.connected {
		return c.pc.Write(b)
	}
	return c.pc.WriteToUDPAddrPort(b, addr)
}

func (c *darwinBatchingConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *darwinBatchingConn) Close() error                       { return c.pc.Close() }
func (c *darwinBatchingConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *darwinBatchingConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *darwinBatchingConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
func (c *darwinBatchingConn) SyscallConn() (syscall.RawConn, error) {
	return c.rc, nil
}

// Debug knobs for evaluating batched I/O; all default to enabled.
//
// TODO(bradfitz): remove or promote these once the evaluation is done.
var (
	// debugMsgx (TS_DEBUG_MSGX) disables recvmsg_x/sendmsg_x use when "0".
	debugMsgx = envknob.RegisterOptBool("TS_DEBUG_MSGX")
	// debugMsgxRXMain (TS_DEBUG_MSGX_RX_MAIN) disables batched reads on
	// unconnected sockets when "0".
	debugMsgxRXMain = envknob.RegisterOptBool("TS_DEBUG_MSGX_RX_MAIN")
	// debugMsgxBatchSize (TS_DEBUG_MSGX_BATCHSIZE) overrides [MaxBatchSize].
	debugMsgxBatchSize = envknob.RegisterInt("TS_DEBUG_MSGX_BATCHSIZE")
)

// msgxUsable reports whether [msgx] may be used: the process and kernel
// checks in [msgx.Available] pass and the debug knob hasn't disabled it.
func msgxUsable() bool {
	if v, ok := debugMsgx().Get(); ok && !v {
		return false
	}
	return msgx.Available()
}

// TryUpgradeToConn upgrades pconn to a [Conn] using recvmsg_x for batched
// reads if the kernel supports it. Writes remain one datagram per syscall on
// an unconnected socket. The rxqOverflowsMetricName and knobs arguments are
// unused on Darwin.
func TryUpgradeToConn(pconn nettype.PacketConn, network string, _ string, _ *controlknobs.Knobs) nettype.PacketConn {
	return tryUpgradeToConn(pconn, network, false)
}

// TryUpgradeConnectedToConn upgrades a connected pconn to a [Conn] using
// recvmsg_x and sendmsg_x if the kernel supports them. The addr passed to
// [Conn.WriteBatchTo] is ignored. The knobs argument is unused on Darwin.
func TryUpgradeConnectedToConn(pconn nettype.PacketConn, network string, _ *controlknobs.Knobs) nettype.PacketConn {
	return tryUpgradeToConn(pconn, network, true)
}

func tryUpgradeToConn(pconn nettype.PacketConn, network string, connected bool) nettype.PacketConn {
	if network != "udp4" && network != "udp6" {
		return pconn
	}
	uc, ok := pconn.(*net.UDPConn)
	if !ok {
		return pconn
	}
	if !msgxUsable() {
		return pconn
	}
	if !connected {
		if v, ok := debugMsgxRXMain().Get(); ok && !v {
			return pconn
		}
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return pconn
	}
	return &darwinBatchingConn{
		pc:        uc,
		rc:        rc,
		connected: connected,
	}
}

// MaxBatchSize returns the number of datagrams a [Conn] returned by
// [TryUpgradeToConn] on this platform can read or write per syscall, or 1 if
// no upgrade is possible.
func MaxBatchSize() int {
	if !msgxUsable() {
		return 1
	}
	if n := debugMsgxBatchSize(); n > 0 {
		return min(n, MaximumWriteBatchSize)
	}
	return min(msgx.MaxBatch, MaximumWriteBatchSize)
}
