// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"bytes"
	"context"
	"errors"
	"expvar"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go4.org/netipx"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
)

func newInjectionTestPacket(data []byte, released *atomic.Int32) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data), OnRelease: func() { released.Add(1) },
	})
}

func TestInjectOutboundPacketBufferOwnership(t *testing.T) {
	for _, state := range []string{"read", "buffered-close", "closed", "canceled", "empty", "oversize", "captured"} {
		t.Run(state, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			_, w := newFakeTUN(t.Logf, bus, false)
			t.Cleanup(func() { w.Close() })
			ctx := context.Background()
			data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
			wantErr := error(nil)
			switch state {
			case "closed":
				w.Close()
				wantErr = ErrClosed
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				wantErr = context.Canceled
			case "empty":
				data = nil
			case "oversize":
				data = make([]byte, MaxPacketSize+1)
				wantErr = errPacketTooBig
			}
			if state == "captured" {
				w.InstallCaptureHook(func(path packet.CapturePath, _ time.Time, got []byte, _ packet.CaptureMeta) {
					if path != packet.SynthesizedToPeer || !bytes.Equal(got, data) {
						t.Errorf("capture = %v, %x", path, got)
					}
				})
			}
			var released atomic.Int32
			pkt := newInjectionTestPacket(data, &released)
			err := w.InjectOutboundPacketBufferContext(ctx, pkt)
			if !errors.Is(err, wantErr) {
				t.Fatalf("InjectOutboundPacketBufferContext = %v, want %v", err, wantErr)
			}
			if state == "read" || state == "buffered-close" || state == "captured" {
				if got := released.Load(); got != 0 {
					t.Fatalf("released %d packets before consuming injection, want 0", got)
				}
				if state == "buffered-close" {
					w.Close()
				} else {
					w.Start()
					slab, packets := getSinglePacketReadArgs()
					n, err := w.InjectionQueue().Read(slab, packets)
					if n != 1 || err != nil {
						t.Fatalf("Read = %d, %v", n, err)
					}
					if got := slab[packets[0].Offset : packets[0].Offset+packets[0].Size]; !bytes.Equal(got, data) {
						t.Errorf("Read = %x, want %x", got, data)
					}
				}
			}
			if got := released.Load(); got != 1 {
				t.Errorf("released %d packets, want 1", got)
			}
		})
	}
}

// Cancel a sender waiting behind another sender on a full queue.
func TestInjectOutboundCancellationBehindBlockedSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := eventbustest.NewBus(t)
		_, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		var released atomic.Int32
		data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
		if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)); err != nil {
			t.Fatal(err)
		}
		blocked := make(chan error, 1)
		go func() { blocked <- w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		canceled := make(chan error, 1)
		go func() { canceled <- w.InjectOutboundPacketBufferContext(ctx, newInjectionTestPacket(data, &released)) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-canceled:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("injection = %v, want context.Canceled", err)
			}
		default:
			t.Fatal("canceled sender is stuck behind a background sender")
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("released %d packets after cancellation, want 1", got)
		}
		select {
		case err := <-blocked:
			t.Fatalf("background sender returned before Wrapper.Close: %v", err)
		default:
		}
		w.Close()
		if err := <-blocked; !errors.Is(err, ErrClosed) {
			t.Fatalf("background injection = %v, want ErrClosed", err)
		}
		if got := released.Load(); got != 3 {
			t.Errorf("released %d packets after Close, want 3", got)
		}
	})
}

func TestInjectOutboundPacketBufferCancellationWithFullQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bus := eventbustest.NewBus(t)
		_, w := newFakeTUN(t.Logf, bus, false)
		t.Cleanup(func() { w.Close() })
		data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
		var released atomic.Int32
		if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- w.InjectOutboundPacketBufferContext(ctx, newInjectionTestPacket(data, &released))
		}()
		// Cancel while the sender waits for queue space.
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("injection = %v, want context.Canceled", err)
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("released %d packets after cancellation, want 1", got)
		}
		w.Start()
		slab, packets := getSinglePacketReadArgs()
		if n, err := w.InjectionQueue().Read(slab, packets); n != 1 || err != nil {
			t.Fatalf("Read accepted packet = %d, %v", n, err)
		}
		if got := released.Load(); got != 2 {
			t.Errorf("released %d packets after Read, want 2", got)
		}
	})
}

// Every injected packet is released exactly once, whether it is read or
// drained by a concurrent Close.
func TestInjectOutboundConcurrentReadAndClose(t *testing.T) {
	w := startedWrapper(t, 1)
	t.Cleanup(func() { w.Close() })
	const writers, count = 8, 64
	var released atomic.Int32
	data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
	// Start Close only after a reader has processed an accepted packet.
	firstReleased := make(chan struct{})
	first := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
		OnRelease: func() {
			released.Add(1)
			close(firstReleased)
		},
	})
	if err := w.InjectOutboundPacketBuffer(first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		wg.Go(func() {
			<-start
			for range count {
				err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released))
				if err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("injection: %v", err)
				}
			}
		})
	}
	// Race injection readers with Close's drain.
	for range 3 {
		q := w.InjectionQueue()
		wg.Go(func() {
			<-start
			slab, packets := getSinglePacketReadArgs()
			for {
				if _, err := q.Read(slab, packets); err != nil {
					return
				}
			}
		})
	}
	wg.Go(func() { <-start; <-firstReleased; w.Close() })
	close(start)
	wg.Wait()
	if got := released.Load(); got != writers*count+1 {
		t.Errorf("released %d packets, want %d", got, writers*count+1)
	}
}

func BenchmarkInjectOutboundPacketBuffer(b *testing.B) {
	bus := eventbustest.NewBus(b)
	_, w := newFakeTUN(b.Logf, bus, false)
	defer w.Close()
	w.Start()
	data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
	defer pkt.DecRef()
	slab, packets := getSinglePacketReadArgs()
	b.ReportAllocs()
	for b.Loop() {
		if err := w.InjectOutboundPacketBuffer(pkt.IncRef()); err != nil {
			b.Fatal(err)
		}
		if _, err := w.InjectionQueue().Read(slab, packets); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTryInjectOutbound(t *testing.T) {
	w := startedWrapper(t, 1)
	t.Cleanup(func() { w.Close() })
	data := udp4("1.2.3.4", "5.6.7.8", 98, 98)
	if err := w.TryInjectOutbound(data); err != nil {
		t.Fatal(err)
	}
	// The queue is full and nothing reads it; this must drop, not block.
	if err := w.TryInjectOutbound(data); !errors.Is(err, ErrInjectionQueueFull) {
		t.Fatalf("TryInjectOutbound on full queue = %v, want ErrInjectionQueueFull", err)
	}
	m, _ := w.metrics.outboundDroppedPacketsTotal.Get(usermetric.DropLabels{Reason: usermetric.ReasonQueueFull}).(*expvar.Int)
	if m == nil || m.Value() != 1 {
		t.Errorf("queue_full drops = %v, want 1", m)
	}
	w.Close()
	if err := w.TryInjectOutbound(data); err != ErrClosed {
		t.Errorf("TryInjectOutbound after Close = %v, want ErrClosed", err)
	}
}

// Replies generated while processing an inbound packet (TSMP pongs and
// TSMP connection rejects) must not block when the injection queue is full
// and its reader is not draining it. The injection queue's reader may be
// blocked behind wireguard-go's device.peers lock, held by RemovePeer,
// while the routine that processes inbound packets must complete before
// that same peer's teardown can finish. A blocking injection on these paths
// deadlocks peer removal against inbound packet processing, as in
// tailscale/corp#45544.
//
// The full queue is the only blocking operation on these paths, so after
// synctest.Wait the reply either completed or is provably stuck on the
// queue; no timeout is needed. A regressed, blocking sender is unblocked
// by closing the Wrapper before failing, so the bubble can settle.
func TestInboundReplyWithFullInjectionQueue(t *testing.T) {
	// fillInjectionQueue queues one packet, filling the injection queue
	// (depth 1), and leaves it unread.
	fillInjectionQueue := func(t *testing.T, w *Wrapper) {
		t.Helper()
		if err := w.TryInjectOutbound(udp4("1.2.3.4", "5.6.7.8", 98, 98)); err != nil {
			t.Fatal(err)
		}
	}
	queueFullDrops := func(w *Wrapper) int64 {
		m, _ := w.metrics.outboundDroppedPacketsTotal.Get(usermetric.DropLabels{Reason: usermetric.ReasonQueueFull}).(*expvar.Int)
		if m == nil {
			return -1
		}
		return m.Value()
	}
	// waitReply returns the reply's filter response, or fails the test if the
	// sender is durably blocked instead. Closing w unblocks a blocking sender.
	waitReply := func(t *testing.T, w *Wrapper, reply func() filter.Response) filter.Response {
		t.Helper()
		done := make(chan filter.Response, 1)
		go func() { done <- reply() }()
		synctest.Wait()
		select {
		case res := <-done:
			return res
		default:
			w.Close()
			synctest.Wait()
			t.Fatal("reply generation blocked on a full injection queue")
			panic("unreachable")
		}
	}

	t.Run("TSMP_pong", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			_, w := newFakeTUN(t.Logf, bus, false)
			t.Cleanup(func() { w.Close() })
			fillInjectionQueue(t, w)

			ipHdr := packet.IP4Header{
				IPProto: ipproto.TSMP,
				Src:     netip.MustParseAddr("1.2.3.4"),
				Dst:     netip.MustParseAddr("100.64.1.2"),
			}
			payload := make([]byte, 9)
			payload[0] = byte(packet.TSMPTypePing)
			pkt := make([]byte, ipHdr.Len()+len(payload))
			ipHdr.Marshal(pkt)
			copy(pkt[ipHdr.Len():], payload)
			pp := new(packet.Parsed)
			pp.Decode(pkt)

			res := waitReply(t, w, func() filter.Response {
				res, _ := w.filterPacketInboundFromWireGuard(pp, nil, nil, nil)
				return res
			})
			if res != filter.DropSilently {
				t.Fatalf("TSMP ping response = %v, want DropSilently", res)
			}
			if got := queueFullDrops(w); got != 1 {
				t.Errorf("queue_full drops = %d, want 1 (the pong)", got)
			}
		})
	})

	t.Run("TSMP_connection_reject", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			_, w := newFakeTUN(t.Logf, bus, false)
			t.Cleanup(func() { w.Close() })
			w.disableFilter = false
			w.SetFilter(filter.NewAllowNone(logger.Discard, new(netipx.IPSet)))
			fillInjectionQueue(t, w)

			pp := new(packet.Parsed)
			pp.Decode(tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000))

			res := waitReply(t, w, func() filter.Response {
				res, _ := w.filterPacketInboundFromWireGuard(pp, nil, nil, nil)
				return res
			})
			if !res.IsDrop() {
				t.Fatalf("SYN rejected by filter = %v, want a drop", res)
			}
			if got := queueFullDrops(w); got != 1 {
				t.Errorf("queue_full drops = %d, want 1 (the reject)", got)
			}
		})
	})
}
