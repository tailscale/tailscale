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
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/windows"
)

// udpRx is the receive half of [UDPConn].
//
// Its exported methods are safe for concurrent use.
// The caller must ensure that the connection is not closed
// while any unexported methods are in flight, unless
// otherwise specified by the method.
type udpRx struct {
	udpNx
	// pendingResultIdx is the index in [udpNx.results]
	// of the next pending result to process.
	pendingResultIdx int
}

// init initializes the receive half of a [UDPConn] with the
// specified underlying connection and options.
func (rx *udpRx) init(conn *conn, options UDPConfig) error {
	// Without URO, the data buffer for each receive request only needs
	// to hold a single packet's payload.
	dataSize := min(options.Rx().MaxPayloadLen(), MaxUDPPayload)
	if err := rx.udpNx.init(conn, dataSize, options.Rx().MemoryLimit()); err != nil {
		return fmt.Errorf("failed to initialize udpRx: %w", err)
	}
	return nil
}

// ReadBatch implements [batching.Conn] by reading messages into msgs.
// It returns the number of messages the caller should evaluate for nonzero len,
// as a zero len message may fall on either side of a nonzero.
// The flags parameter is reserved for future use and must be zero.
func (rx *udpRx) ReadBatch(msgs []ipv6.Message, flags int) (n int, err error) {
	// Prevent the connection from closing while in use.
	if err := rx.conn.acquire(); err != nil {
		return 0, &net.OpError{Op: "read", Net: rx.conn.Network(), Source: rx.conn.LocalAddr(), Err: err}
	}
	defer rx.conn.release()

	rx.mu.Lock()
	defer rx.mu.Unlock()
	// Keep trying to read until we get at least one message or an error.
	for n == 0 && err == nil {
		if err := rx.awaitCompletionsLocked(); err != nil {
			return 0, err
		}
		n, err = rx.processCompletionsLocked(msgs)
	}
	// Always try to post more receive requests, even if an error
	// occurred while processing completed ones.
	if postErr := rx.postReceiveRequestsLocked(); postErr != nil {
		err = errors.Join(err, postErr)
	}
	if err != nil {
		err = &net.OpError{Op: "read", Net: rx.conn.Network(), Source: rx.conn.LocalAddr(), Err: err}
	}
	return n, err
}

// ReadFromUDPAddrPort implements [nettype.PacketConn.ReadFromUDPAddrPort].
func (rx *udpRx) ReadFromUDPAddrPort(p []byte) (n int, addr netip.AddrPort, err error) {
	n, netAddr, err := rx.ReadFrom(p)
	if netAddr != nil {
		addr = netAddr.(*net.UDPAddr).AddrPort()
	}
	return n, addr, err
}

// ReadFrom implements [net.PacketConn.ReadFrom].
func (rx *udpRx) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	msgs := []ipv6.Message{{
		Buffers: [][]byte{p},
	}}
	numMsgs, err := rx.ReadBatch(msgs, 0)
	if numMsgs != 0 {
		n = msgs[0].N
		addr = msgs[0].Addr
	}
	return n, addr, err
}

// postReceiveRequests posts available receive requests to the
// RIO request queue. The caller must ensure that the connection
// is not closed until this call returns.
func (rx *udpRx) postReceiveRequests() error {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return rx.postReceiveRequestsLocked()
}

// postReceiveRequestsLocked posts all available receive requests
// to the RIO request queue.
// rx.mu must be held.
func (rx *udpRx) postReceiveRequestsLocked() (err error) {
	return rx.conn.postReceiveRequests(rx.requests.AcquireSeq())
}

// awaitCompletionsLocked dequeues completed receive requests, returning when
// there's at least one completion to process, the connection is closed,
// or an error occurs.
// rx.mu must be held.
func (rx *udpRx) awaitCompletionsLocked() error {
	if rx.pendingResultIdx < len(rx.results) {
		// We have already dequeued some completions that haven't been
		// fully processed yet. Return immediately.
		return nil
	}

	rx.results = rx.results[:cap(rx.results)]
	rx.pendingResultIdx = 0

	var count uint32
	for {
		if count = winrio.DequeueCompletion(rx.cq, rx.results[:]); count != 0 {
			// Got new completions to process, no need to wait.
			break
		}
		// Otherwise, arm the notification...
		if err := winrio.Notify(rx.cq); err != nil {
			return err
		}
		// ...and wait until RIO signals that more completions are available
		// or the connection is closed.
		handles := []windows.Handle{rx.conn.closedEvt, rx.hasCompletionsEvt}
		switch evtIdx, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE); {
		case err != nil:
			return fmt.Errorf("waiting for completed receives failed: %w", err)
		case evtIdx == 0:
			return net.ErrClosed
		case evtIdx == 1:
			continue // try dequeueing completions again
		default:
			panic("unreachable")
		}
	}
	rx.results = rx.results[:count]
	return nil
}

// processCompletionsLocked processes completed receive requests and fills msgs
// with the received packets. It returns the number of messages the caller
// should evaluate for nonzero len, as a zero len message may fall on either
// side of a nonzero.
// rx.mu must be held.
func (rx *udpRx) processCompletionsLocked(msgs []ipv6.Message) (n int, err error) {
	firstResultIdx := rx.pendingResultIdx

	defer func() {
		// Always release processed results, even if an error occurred.
		rx.requests.ReleaseN(rx.pendingResultIdx - firstResultIdx)
	}()

	for rx.pendingResultIdx < len(rx.results) && n < len(msgs) {
		res := &rx.results[rx.pendingResultIdx]
		req := (*request)(unsafe.Pointer(uintptr(res.RequestContext)))
		r, err := req.CompleteReceive(res.Status, res.BytesTransferred)
		if err != nil {
			rx.pendingResultIdx++
			if err == windows.WSAEMSGSIZE {
				// The packet is larger than [RxConfig.MaxPayloadLen].
				// Skip it and try to process the next one, if any.
				continue
			}
			// In case of other errors, skip the packet and return
			// the error to the caller.
			return n, err
		}
		// TODO(nickkhyl): Maintain an LRU cache of remote addresses to
		// avoid allocating a new [netip.AddrPort] / [net.UDPAddr] for each packet.
		// Profiling suggests this accounts for ~5% of total processing time.
		udpAddr, err := r.RemoteAddr().ToUDPAddr()
		if err != nil {
			return n, fmt.Errorf("invalid remote address: %w", err)
		}

		if r.Len() <= len(msgs[n].Buffers[0]) {
			// TODO(nickkhyl): avoid the copy? We could transfer ownership of the underlying
			// buffer to the reader until the next read or an explicit release.
			msgs[n].N = copy(msgs[n].Buffers[0], r.Bytes())
		} else {
			msgs[n].N = 0 // packet is too large; ignore it
		}
		msgs[n].Addr = udpAddr
		rx.pendingResultIdx++
		n++
	}
	return n, nil
}
