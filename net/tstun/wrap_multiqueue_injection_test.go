// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

// injectionTestQueue is a native TUN queue used by injection tests.
type injectionTestQueue struct {
	closed  <-chan struct{}
	packets chan []byte
}

func (*injectionTestQueue) File() *os.File { return nil }

func (q *injectionTestQueue) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case <-q.closed:
		return 0, io.EOF
	case p := <-q.packets:
		copy(slab[tun.ReadPacketSpacing:], p)
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: len(p)}
		return 1, nil
	}
}

func newMultiQueueInjectionTestWrapper(t *testing.T) (*fakeTUN, *Wrapper) {
	t.Helper()
	d := newFakeMQ(4)
	for i := range d.queues {
		d.queues[i] = &injectionTestQueue{closed: d.closechan, packets: make(chan []byte, 1)}
	}
	w := Wrap(t.Logf, d, new(usermetric.Registry), eventbustest.NewBus(t))
	w.disableFilter = true
	w.Start()
	t.Cleanup(func() { w.Close() })
	return d, w
}

func TestMultiQueueOutboundInjectionProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, w := newMultiQueueInjectionTestWrapper(t)
		queues := w.Queues()[:len(d.queues)]
		data := udp4("100.64.1.2", "100.64.1.3", 1234, 5678)
		var released atomic.Int32
		if err := w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)); err != nil {
			t.Fatal(err)
		}
		blocked := make(chan error, 1)
		go func() { blocked <- w.InjectOutboundPacketBuffer(newInjectionTestPacket(data, &released)) }()
		synctest.Wait()

		// The injection queue has no reader yet. Its full handoff and blocked
		// sender must not stop reads/filtering on any native queue.
		read := make(chan int, len(queues))
		closed := make(chan error, len(queues))
		for i := range queues {
			go func() {
				slab, packets := getSinglePacketReadArgs()
				n, err := queues[i].Read(slab, packets)
				if n != 1 || err != nil || !bytes.Equal(slab[packets[0].Offset:packets[0].Offset+packets[0].Size], data) {
					t.Errorf("queue %d read = %d, %v", i, n, err)
				}
				read <- i
				_, err = queues[i].Read(slab, packets)
				closed <- err
			}()
			d.queues[i].(*injectionTestQueue).packets <- data
		}
		synctest.Wait()
		if got := len(read); got != len(queues) {
			t.Fatalf("%d native queues made progress, want %d", got, len(queues))
		}
		select {
		case err := <-blocked:
			t.Fatalf("full injection handoff unexpectedly unblocked: %v", err)
		default:
		}
		if got := released.Load(); got != 0 {
			t.Fatalf("released = %d, want 0", got)
		}

		slab, packets := getSinglePacketReadArgs()
		for range 2 {
			n, err := w.InjectionQueue().Read(slab, packets)
			if n != 1 || err != nil || !bytes.Equal(slab[packets[0].Offset:packets[0].Offset+packets[0].Size], data) {
				t.Fatalf("injection queue read = %d, %v", n, err)
			}
		}
		if err := <-blocked; err != nil {
			t.Fatal(err)
		}
		if got := released.Load(); got != 2 {
			t.Fatalf("released = %d, want 2", got)
		}
		w.Close()
		for range len(queues) {
			if err := <-closed; !errors.Is(err, io.EOF) {
				t.Errorf("native read after Close = %v, want EOF", err)
			}
		}
	})
}
