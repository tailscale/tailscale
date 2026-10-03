// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestQueue(t *testing.T, size int) *queue {
	t.Helper()
	q := &queue{
		c:        make(chan *stack.PacketBuffer, size),
		closedCh: make(chan struct{}),
	}
	t.Cleanup(func() {
		q.Close()
		q.Drain()
	})
	return q
}

func newQueueTestPacket(released *atomic.Int32) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		OnRelease: func() { released.Add(1) },
	})
}

func TestQueueReadAndDrain(t *testing.T) {
	q := newTestQueue(t, 2)
	var released atomic.Int32
	var first *stack.PacketBuffer
	for i := range 2 {
		pkt := newQueueTestPacket(&released)
		if i == 0 {
			first = pkt
		}
		err := q.Write(pkt)
		pkt.DecRef()
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("released %d queued packets; want 0", got)
	}
	if got := q.Num(); got != 2 {
		t.Fatalf("Num = %d; want 2", got)
	}
	pkt := q.Read()
	if pkt != first {
		t.Fatalf("Read = %p; want %p", pkt, first)
	}
	pkt.DecRef()
	if got := released.Load(); got != 1 {
		t.Errorf("released %d packets after Read; want 1", got)
	}
	q.Close()
	if got := q.Drain(); got != 1 {
		t.Errorf("Drain = %d; want 1", got)
	}
	if got := released.Load(); got != 2 {
		t.Errorf("released %d packets after Drain; want 2", got)
	}
	if pkt := q.Read(); pkt != nil {
		pkt.DecRef()
		t.Error("Read returned a packet after Drain")
	}
}

func TestQueueWriteFull(t *testing.T) {
	q := newTestQueue(t, 1)
	var released atomic.Int32
	queued := newQueueTestPacket(&released)
	err := q.Write(queued)
	queued.DecRef()
	if err != nil {
		t.Fatalf("first Write: %v", err)
	}
	pkt := newQueueTestPacket(&released)
	done := make(chan tcpip.Error, 1)
	go func() { done <- q.Write(pkt) }()
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		q.Close()
		<-done
		pkt.DecRef()
		t.Fatal("Write blocked on a full queue for 2s")
	}
	if got := released.Load(); got != 0 {
		t.Errorf("released %d packets before caller DecRef; want 0", got)
	}
	pkt.DecRef()
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Errorf("full queue Write = %v; want ErrNoBufferSpace", err)
	}
	if got := released.Load(); got != 1 {
		t.Errorf("released %d packets after rejected Write; want 1", got)
	}
	if got := q.Num(); got != 1 {
		t.Errorf("Num = %d; want 1", got)
	}
	q.Close()
	if got := q.Drain(); got != 1 {
		t.Errorf("Drain = %d; want 1", got)
	}
	if got := released.Load(); got != 2 {
		t.Errorf("released %d packets after Drain; want 2", got)
	}
}

func TestQueueWriteClosed(t *testing.T) {
	for _, state := range []string{"closed", "close-signaled"} {
		t.Run(state, func(t *testing.T) {
			q := newTestQueue(t, 0)
			if state == "closed" {
				q.Close()
			} else {
				// Model Close signaling writers before acquiring q.mu.
				q.closeOnce.Do(func() { close(q.closedCh) })
			}
			var released atomic.Int32
			pkt := newQueueTestPacket(&released)
			err := q.Write(pkt)
			if got := released.Load(); got != 0 {
				t.Errorf("released %d packets before caller DecRef; want 0", got)
			}
			pkt.DecRef()
			if _, ok := err.(*tcpip.ErrClosedForSend); !ok {
				t.Errorf("Write = %v; want ErrClosedForSend", err)
			}
			if got := released.Load(); got != 1 {
				t.Errorf("released %d packets; want 1", got)
			}
		})
	}
}

func TestQueueConcurrentWriteAndClose(t *testing.T) {
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
		q.Close()
	})
	close(start)
	wg.Wait()
	q.Drain()
	if got := released.Load(); got != writers*packets {
		t.Errorf("released %d packets; want %d", got, writers*packets)
	}
}
