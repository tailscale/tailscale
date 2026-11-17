// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestQueue(t testing.TB, size int) *queue {
	t.Helper()
	q := &queue{c: make(chan *stack.PacketBuffer, size), closedCh: make(chan struct{})}
	t.Cleanup(func() { q.Close(); q.Drain() })
	return q
}

func newQueueTestPacket(released *atomic.Int32) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{OnRelease: func() { released.Add(1) }})
}

func TestQueueWriteFull(t *testing.T) {
	q := newTestQueue(t, 1)
	var released atomic.Int32
	for i, want := range []tcpip.Error{nil, &tcpip.ErrNoBufferSpace{}} {
		pkt := newQueueTestPacket(&released)
		err := q.Write(pkt) // must not block
		pkt.DecRef()
		if fmt.Sprintf("%T", err) != fmt.Sprintf("%T", want) {
			t.Fatalf("Write %d = %v, want %v", i, err, want)
		}
	}
	// Only the rejected packet is released; the queued one is retained.
	if got := released.Load(); got != 1 {
		t.Errorf("released %d packets, want 1", got)
	}
	if got := q.Num(); got != 1 {
		t.Errorf("Num = %d, want 1", got)
	}
}

func TestQueueWriteClosed(t *testing.T) {
	for _, state := range []string{"closed", "close-signaled"} {
		t.Run(state, func(t *testing.T) {
			q := newTestQueue(t, 0)
			if state == "closed" {
				q.Close()
			} else {
				q.closeOnce.Do(func() { close(q.closedCh) })
			}
			var released atomic.Int32
			pkt := newQueueTestPacket(&released)
			err := q.Write(pkt)
			if got := released.Load(); got != 0 {
				t.Errorf("released %d packets before caller DecRef, want 0", got)
			}
			pkt.DecRef()
			if _, ok := err.(*tcpip.ErrClosedForSend); !ok {
				t.Errorf("Write = %v, want ErrClosedForSend", err)
			}
			if got := released.Load(); got != 1 {
				t.Errorf("released %d packets, want 1", got)
			}
		})
	}
}

func TestQueueConcurrentWriteReadAndClose(t *testing.T) {
	q := newTestQueue(t, 8)
	const writers, packets = 8, 64
	var released atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		wg.Go(func() {
			<-start
			for range packets {
				pkt := newQueueTestPacket(&released)
				err := q.Write(pkt)
				pkt.DecRef()
				switch err.(type) {
				case nil, *tcpip.ErrNoBufferSpace, *tcpip.ErrClosedForSend:
				default:
					t.Errorf("Write: unexpected error %v", err)
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		for {
			pkt := q.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			pkt.DecRef()
		}
	})
	wg.Go(func() { <-start; q.Close() })
	close(start)
	wg.Wait()
	q.Drain()
	if got := released.Load(); got != writers*packets {
		t.Errorf("released %d packets, want %d", got, writers*packets)
	}
}
