// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"bytes"
	"context"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/util/testenv"
)

// forTest is an unexported type to hide the test-only methods on [Wrapper]
// from godoc.
type forTest struct {
	w *Wrapper

	tickets []chan struct{} // authorize reads, one channel per queue of w.
	results chan readResult
}

// readResult is the outcome of a single [tun.Queue.Read].
type readResult struct {
	pkts [][]byte
	err  error
}

// ForTest returns a handle to test-only methods on t. The resulting
// type is unexported to make it very obvious in godoc that this is
// not stable API. This method panics if called outside of tests,
// which also centralizes all must-be-in-tests validation.
func (t *Wrapper) ForTest() *forTest {
	testenv.AssertInTest()
	return t.forTest.Get(func() *forTest {
		qs := t.Queues()
		f := &forTest{
			w:       t,
			tickets: make([]chan struct{}, len(qs)),
			results: make(chan readResult),
		}
		for i, q := range qs {
			f.tickets[i] = make(chan struct{}, 1)
			go f.read(f.tickets[i], q)
		}
		return f
	})
}

// read hands the outcome of every authorized read of q to [forTest.ReadN],
// until a read fails or f's Wrapper is closed.
func (f *forTest) read(tickets <-chan struct{}, q tun.Queue) {
	slab := make([]byte, MaxPacketSize+(2*tun.ReadPacketSpacing))
	packets := make([]tun.ReadPacket, 1)
	for {
		select {
		case <-tickets:
		case <-f.w.closed:
			return
		}
		n, err := q.Read(slab, packets)
		// Copy the packets out, reuse the slab.
		pkts := make([][]byte, 0, n)
		for _, meta := range packets[:n] {
			pkts = append(pkts, bytes.Clone(slab[meta.Offset:meta.Offset+meta.Size]))
		}
		select {
		case f.results <- readResult{pkts, err}:
		case <-f.w.closed:
			return
		}
		if err != nil {
			return
		}
	}
}

// ReadN returns result of the next n reads across all queues.
// The packets are copies.
func (f *forTest) ReadN(ctx context.Context, n int) ([][]byte, error) {
	var pkts [][]byte
	for range n {
		for _, tickets := range f.tickets {
			select {
			case tickets <- struct{}{}:
			default:
			}
		}
		select {
		case r := <-f.results:
			pkts = append(pkts, r.pkts...)
			if r.err != nil {
				return pkts, r.err
			}
		case <-f.w.closed:
			return pkts, ErrClosed
		case <-ctx.Done():
			return pkts, ctx.Err()
		}
	}
	return pkts, nil
}
