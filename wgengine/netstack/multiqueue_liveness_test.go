// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/tstun"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

type queueTestTUN struct {
	tun.Device
	queues []tun.Queue
	closed chan struct{}
}

func newQueueTestTUN(n int) *queueTestTUN {
	d := &queueTestTUN{Device: tstun.NewFake(), closed: make(chan struct{})}
	for range n {
		d.queues = append(d.queues, &queueTestTUNQueue{closed: d.closed, packets: make(chan []byte, 1)})
	}
	return d
}

func (d *queueTestTUN) Queues() []tun.Queue { return d.queues }
func (d *queueTestTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	return d.queues[0].Read(slab, packets)
}
func (d *queueTestTUN) WriteTo(_ int, bufs [][]byte, offset int) (int, error) {
	return d.Write(bufs, offset)
}
func (d *queueTestTUN) Close() error {
	close(d.closed)
	return d.Device.Close()
}

type queueTestTUNQueue struct {
	closed  <-chan struct{}
	packets chan []byte
}

func (*queueTestTUNQueue) File() *os.File { return nil }
func (q *queueTestTUNQueue) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	select {
	case <-q.closed:
		return 0, io.EOF
	case data := <-q.packets:
		copy(slab[tun.ReadPacketSpacing:], data)
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: len(data)}
		return 1, nil
	}
}

// Concurrent native TUN reads must not block on synchronous netstack replies
// when the outbound queue is full.
func TestMultiQueueNetstackReplyWithFullQueue(t *testing.T) {
	const queues = 4
	s, ep := newQueueTestStack(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ns := &Impl{ctx: ctx, ipstack: s, linkEP: ep, logf: t.Logf}
	ns.ready.Store(true)
	d := newQueueTestTUN(queues)
	w := tstun.Wrap(t.Logf, d, new(usermetric.Registry), eventbustest.NewBus(t))
	defer w.Close()
	w.PreFilterPacketOutboundToWireGuardNetstackIntercept = ns.handleLocalPackets
	w.Start()

	var released atomic.Int32
	filler := newQueueTestPacket(&released)
	err := ep.outboundQueues[outboundToHost].Write(filler)
	filler.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	ack := queueTestACK(queueTestLocalIP, serviceIP)
	th := header.TCP(ack.TransportHeader().Slice())
	pseudo := tun.PseudoHeaderChecksum(uint8(header.TCPProtocolNumber), queueTestLocalIP.AsSlice(), serviceIP.AsSlice(), uint16(len(th)))
	th.SetChecksum(^tun.Checksum(th, pseudo))
	data := append([]byte(nil), stack.PayloadSince(ack.NetworkHeader()).AsSlice()...)
	ack.DecRef()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, q := range w.Queues()[:queues] {
		d.queues[i].(*queueTestTUNQueue).packets <- data
		wg.Go(func() {
			<-start
			slab := make([]byte, tstun.MaxPacketSize+2*tun.ReadPacketSpacing)
			n, err := q.Read(slab, make([]tun.ReadPacket, 1))
			if n != 0 || err != nil {
				t.Errorf("intercepted read = %d, %v; want 0, nil", n, err)
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	close(start)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		ep.Close()
		w.Close()
		<-done
		t.Fatal("a TUN queue blocked generating a reply into a full netstack queue")
	}
	if got := ep.queueFullDropped[outboundToHost].Value(); got != queues {
		t.Fatalf("queue-full drops = %d, want %d", got, queues)
	}
	// Releasing capacity must restore delivery without canceling netstack.
	ep.Read(outboundToHost).DecRef()
	ep.DeliverLoopback(queueTestACK(queueTestLocalIP, serviceIP))
	requireQueueTestReset(t, ep, outboundToHost)
	if got := released.Load(); got != 1 {
		t.Errorf("filler released %d times, want 1", got)
	}
}
