// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn/winrio"
	"golang.org/x/sys/windows"
	"tailscale.com/net/packet"
)

// udpTx is the transmit half of [UDPConn].
//
// Its exported methods are safe for concurrent use.
// The caller must ensure that the connection is not closed
// while any unexported methods are in flight, unless
// otherwise specified by the method.
type udpTx struct {
	udpNx
}

// init initializes the transmit half of a [UDPConn] with the
// specified underlying connection and options.
func (tx *udpTx) init(conn *conn, options UDPConfig) error {
	// Without USO, the data buffer for each send request only needs to hold
	// a single packet's payload.
	dataSize := min(options.Tx().MaxPayloadLen(), MaxUDPPayload)
	if err := tx.udpNx.init(conn, dataSize, options.Tx().MemoryLimit()); err != nil {
		return fmt.Errorf("failed to initialize udpTx: %w", err)
	}
	return nil
}

// WriteBatchTo implements [batching.Conn.WriteBatchTo] by writing
// buffs to the specified remote address.
//
// If geneve.VNI.IsSet(), then geneve is encoded into the space preceding
// offset, and offset must equal [packet.GeneveFixedHeaderLength].
// Otherwise, the space preceding offset is ignored.
func (tx *udpTx) WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error {
	if tx.conn.IsDualStack() && addr.Addr().Is4() {
		// Convert to an IPv4-mapped IPv6 address
		addr = netip.AddrPortFrom(netip.AddrFrom16(addr.Addr().As16()), addr.Port())
	}
	if err := tx.writeBatchTo(buffs, addr, geneve, offset); err != nil {
		return &net.OpError{Op: "write", Net: tx.conn.Network(), Source: tx.conn.LocalAddr(), Addr: net.UDPAddrFromAddrPort(addr), Err: err}
	}
	return nil
}

// writeBatchTo implements [udpTx.WriteBatchTo]. It returns an
// error if the connection is already closed and prevents the
// connection from closing until it returns.
func (tx *udpTx) writeBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) (err error) {
	if len(buffs) == 0 {
		return nil
	}

	raddr, err := rawSockaddrFromAddrPort(addr)
	if err != nil {
		return fmt.Errorf("failed to convert address: %w", err)
	}

	// Prevent the connection from closing while in use.
	if err := tx.conn.acquire(); err != nil {
		return err
	}
	defer tx.conn.release()

	tx.mu.Lock()
	defer tx.mu.Unlock()

	n := 0
	defer func() {
		if n != 0 {
			if commitErr := tx.conn.commitSendRequests(); commitErr != nil {
				err = errors.Join(err, commitErr)
			}
		}
	}()

	for n < len(buffs) {
		if tx.conn.IsClosed() {
			return net.ErrClosed
		}
		if err := tx.drainCompletionsLocked(); err != nil {
			return err
		}

		req := tx.requests.Peek()
		w := req.Writer()
		w.SetRemoteAddr(raddr)

		if geneve.VNI.IsSet() {
			geneveHeader := w.Reserve(packet.GeneveFixedHeaderLength)
			geneve.Encode(geneveHeader[:])
		}
		if _, err := w.Write(buffs[n][offset:]); err != nil {
			return err
		}

		if err = tx.conn.postSendRequest(req, winrio.MsgDefer); err != nil {
			return fmt.Errorf("failed to post send request: %w", err)
		}

		tx.requests.Advance() // advance after posting the request
		n++
	}
	return nil
}

// WriteToUDPAddrPort implements [nettype.PacketConn.WriteToUDPAddrPort].
func (tx *udpTx) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (n int, err error) {
	if err := tx.WriteBatchTo([][]byte{p}, addr, packet.GeneveHeader{}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteTo implements [net.PacketConn.WriteTo].
func (tx *udpTx) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, &net.OpError{
			Op:     "write",
			Net:    tx.conn.Network(),
			Source: tx.conn.LocalAddr(),
			Addr:   addr,
			Err:    net.InvalidAddrError("address is not a *net.UDPAddr"),
		}
	}
	return tx.WriteToUDPAddrPort(p, udpAddr.AddrPort())
}

// drainCompletionsLocked dequeues and processes completed send requests
// until the request ring is not full (i.e., more requests can be posted)
// or the closedEvt is signaled.
//
// tx.mu must be held, and the caller must ensure that the connection
// is not closed until this call returns.
func (tx *udpTx) drainCompletionsLocked() error {
	var count uint32
	for {
		if count = winrio.DequeueCompletion(tx.cq, tx.results[:cap(tx.results)]); count != 0 {
			// Got new completions to process, no need to wait.
			break
		}
		if !tx.requests.IsFull() {
			// No completions to process, but also not all requests are in-flight,
			// so no need to wait.
			break
		}
		// Otherwise, if all requests are in flight, commit any deferred sends.
		tx.conn.commitSendRequests()
		// Then arm the notification...
		if err := winrio.Notify(tx.cq); err != nil {
			return err
		}
		// ...and wait for either RIO to signal that more completions are available,
		// or the connection to be closed.
		handles := []windows.Handle{tx.conn.closedEvt, tx.hasCompletionsEvt}
		switch evtIdx, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE); {
		case err != nil:
			return fmt.Errorf("waiting for completed sends failed: %w", err)
		case evtIdx == 0:
			return net.ErrClosed
		case evtIdx == 1:
			continue // try dequeueing completions again
		default:
			panic("unreachable")
		}
	}
	for _, res := range tx.results[:count] {
		req := (*request)(unsafe.Pointer(uintptr(res.RequestContext)))
		if err := req.CompleteSend(res.Status, res.BytesTransferred); err != nil {
			// TODO(nickkhyl): Returning an error here does not make much sense.
			// Increment a send error metric or log the error instead?
		}
	}
	tx.results = tx.results[:0]
	tx.requests.ReleaseN(int(count))
	return nil
}
