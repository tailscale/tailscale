// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/tstun"
	"tailscale.com/tsd"
)

var queueTestLocalIP = netip.MustParseAddr("100.64.1.2")

// newQueueTestStack uses the production destination classifier, but small
// queues and no consumers so tests can deterministically force saturation.
func newQueueTestStack(t testing.TB, size int) (*stack.Stack, *linkEndpoint) {
	t.Helper()
	ns := &Impl{}
	ns.atomicIsLocalIPFunc.Store(func(a netip.Addr) bool { return a == queueTestLocalIP })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ep := newLinkEndpoint(size, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{queueTestLocalIP, serviceIP} {
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          header.IPv4ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})
	return s, ep
}

// An ACK without an endpoint bypasses the TCP forwarder and generates a
// synchronous reset in gVisor. DeliverLoopback marks the checksum validated.
func queueTestACK(src, dst netip.Addr) *stack.PacketBuffer {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 40})
	header.TCP(pkt.TransportHeader().Push(20)).Encode(&header.TCPFields{
		SrcPort: 12345, DstPort: 54321, DataOffset: 20, Flags: header.TCPFlagAck, AckNum: 1,
	})
	ih := header.IPv4(pkt.NetworkHeader().Push(20))
	ih.Encode(&header.IPv4Fields{
		TotalLength: 40, TTL: 64, Protocol: uint8(header.TCPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.As4()), DstAddr: tcpip.AddrFrom4(dst.As4()),
	})
	ih.SetChecksum(^ih.CalculateChecksum())
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	return pkt
}

func requireQueueTestReset(t *testing.T, ep *linkEndpoint, dest outboundQueue) {
	t.Helper()
	pkt := ep.Read(dest)
	if pkt == nil {
		t.Fatal("gVisor did not enqueue a reset")
	}
	defer pkt.DecRef()
	if !header.TCP(pkt.TransportHeader().Slice()).Flags().Contains(header.TCPFlagRst) {
		t.Fatal("reply is not a TCP reset")
	}
}

func TestLoopbackReplyWithFullQueue(t *testing.T) {
	_, ep := newQueueTestStack(t, 1)
	// Model the consumer dequeuing a packet, then another producer refilling
	// the queue before DeliverLoopback synchronously produces its reply.
	ack := queueTestACK(queueTestLocalIP, queueTestLocalIP)
	var pkts stack.PacketBufferList
	pkts.PushBack(ack)
	n, err := ep.WritePackets(pkts)
	ack.DecRef()
	if n != 1 || err != nil {
		t.Fatalf("WritePackets = %d, %v", n, err)
	}
	delivering := ep.Read(outboundLoopback)
	var released atomic.Int32
	filler := newQueueTestPacket(&released)
	err = ep.outboundQueues[outboundLoopback].Write(filler)
	filler.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { ep.DeliverLoopback(delivering); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		ep.Close()
		<-done
		t.Fatal("loopback consumer blocked writing its reply into its own full queue")
	}
	if got := ep.Read(outboundLoopback); got != filler {
		if got != nil {
			got.DecRef()
		}
		t.Fatalf("Read = %p, want queued packet %p", got, filler)
	} else {
		got.DecRef()
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("queued packet released %d times, want 1", got)
	}
	// Recovery must happen before cancellation or closing the endpoint.
	ep.DeliverLoopback(queueTestACK(queueTestLocalIP, queueTestLocalIP))
	requireQueueTestReset(t, ep, outboundLoopback)
}

func TestCloseWithFullOutboundQueues(t *testing.T) {
	ns := makeNetstack(t, func(ns *Impl) { ns.ProcessLocalIPs = true })
	if err := ns.ipstack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(queueTestLocalIP.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	laddr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(queueTestLocalIP.As4()), Port: 8080}
	ln, err := gonet.ListenTCP(ns.ipstack, laddr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, ns.ipstack, laddr, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	// With an established connection, stack shutdown must generate a reset.
	// Stop all readers and fill all three queues before triggering that abort.
	ns.ctxCancel()
	ns.injectWG.Wait()
	var released atomic.Int32
	var queued int32
	for _, q := range ns.linkEP.outboundQueues {
		if q == nil {
			continue
		}
		for range cap(q.c) {
			pkt := newQueueTestPacket(&released)
			err := q.Write(pkt)
			pkt.DecRef()
			if err != nil {
				t.Fatal(err)
			}
			queued++
		}
	}
	done := make(chan struct{})
	go func() { ns.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		ns.linkEP.Close()
		<-done
		t.Fatal("Close blocked with full outbound queues")
	}
	if got := released.Load(); got != queued {
		t.Errorf("released %d queued packets, want %d", got, queued)
	}
}

func TestCloseWithBlockedOutboundInjection(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(fmt.Sprintf("queues=%d", queues), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testCloseWithBlockedOutboundInjection(t, queues)
			})
		})
	}
}

func testCloseWithBlockedOutboundInjection(t *testing.T, queues int) {
	// Leave InjectionQueue unread; netstack shutdown must cancel the sender
	// without closing the shared Wrapper.
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	tw := tstun.Wrap(t.Logf, newQueueTestTUN(queues), sys.UserMetricsRegistry(), sys.Bus.Get())
	t.Cleanup(func() { tw.Close() })
	if err := tw.InjectOutbound([]byte{1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ns := &Impl{ctx: ctx, ctxCancel: cancel, tundev: tw, logf: t.Logf}
	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return false })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ns.linkEP = newLinkEndpoint(1, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	// This test only runs the injection pump; no protocol workers are needed.
	ns.ipstack = stack.New(stack.Options{})
	if err := ns.ipstack.CreateNIC(nicID, ns.linkEP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tw.Close(); ns.Close() })
	q := ns.linkEP.outboundQueues[outboundToWireGuard]
	var released atomic.Int32
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{1}), OnRelease: func() { released.Add(1) },
	})
	err := q.Write(pkt)
	pkt.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	tw.Start()
	nativeReadDone := make(chan error, queues)
	for _, q := range tw.Queues()[:queues] {
		go func() {
			slab := make([]byte, tstun.MaxPacketSize+2*tun.ReadPacketSpacing)
			_, err := q.Read(slab, make([]tun.ReadPacket, 1))
			nativeReadDone <- err
		}()
	}
	ns.injectWG.Go(ns.injectToWireGuard)
	// With InjectionQueue full and unread, wait until the pump has blocked
	// in injection, not merely dequeued its packet.
	synctest.Wait()
	if q.Num() != 0 {
		t.Fatal("injector has not dequeued packet")
	}
	if got := released.Load(); got != 0 {
		t.Fatalf("released %d packets before shutdown, want 0", got)
	}
	closed := make(chan error, 1)
	go func() { closed <- ns.Close() }()
	synctest.Wait()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("netstack Close required closing the Wrapper to cancel injection")
	}
	if got := released.Load(); got != 1 {
		t.Errorf("canceled packet released %d times, want 1", got)
	}
	// The shared Wrapper must remain usable after netstack stops injecting.
	slab := make([]byte, tstun.MaxPacketSize+2*tun.ReadPacketSpacing)
	if n, err := tw.InjectionQueue().Read(slab, make([]tun.ReadPacket, 1)); n != 1 || err != nil {
		t.Fatalf("Read after netstack Close = %d, %v", n, err)
	}
	if err := tw.InjectOutbound([]byte{2}); err != nil {
		t.Fatalf("InjectOutbound after netstack Close: %v", err)
	}
	select {
	case err := <-nativeReadDone:
		t.Fatalf("netstack Close terminated a native queue reader: %v", err)
	default:
	}
	tw.Close()
	for range queues {
		if err := <-nativeReadDone; err != io.EOF {
			t.Errorf("native read after Wrapper Close = %v, want EOF", err)
		}
	}
}

func TestInjectToWireGuardStopsOnClosedWrapper(t *testing.T) {
	sys := tsd.NewSystem()
	t.Cleanup(sys.Bus.Get().Close)
	tw := tstun.Wrap(t.Logf, tstun.NewFake(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ep := newLinkEndpoint(1, 1280, "", groNotSupported, nil)
	defer ep.Close()
	var released atomic.Int32
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{1}), OnRelease: func() { released.Add(1) },
	})
	err := ep.outboundQueues[outboundToWireGuard].Write(pkt)
	pkt.DecRef()
	if err != nil {
		t.Fatal(err)
	}
	ns := &Impl{ctx: ctx, tundev: tw, linkEP: ep, logf: t.Logf}
	done := make(chan struct{})
	go func() { ns.injectToWireGuard(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("injectToWireGuard did not stop on a closed Wrapper")
	}
	if ctx.Err() != nil {
		t.Fatal("netstack context should still be active")
	}
	if got := released.Load(); got != 1 {
		t.Errorf("rejected packet released %d times, want 1", got)
	}
}

// Queue-full drops are reported to gVisor, which counts them. UDP sockets do
// not see ENOBUFS (as on Linux without IP_RECVERR), so forwarded UDP flows
// survive full queues.
func TestUDPWriteWithFullQueue(t *testing.T) {
	ns := &Impl{}
	ns.atomicIsLocalIPFunc.Store(func(a netip.Addr) bool { return a == queueTestLocalIP })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ep := newLinkEndpoint(1, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	t.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatal(err)
	}
	local := tcpip.AddrFrom4(queueTestLocalIP.As4())
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: local.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	c, err := gonet.DialUDP(s,
		&tcpip.FullAddress{NIC: nicID, Addr: local, Port: 1000},
		&tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4([4]byte{100, 64, 9, 9}), Port: 2000},
		header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 2 {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if got := ep.queueFullDropped[outboundToWireGuard].Value(); got != 1 {
		t.Errorf("queue-full drops = %d, want 1", got)
	}
	if got := s.Stats().NICs.TxPacketsDroppedNoBufferSpace.Value(); got != 1 {
		t.Errorf("gVisor TxPacketsDroppedNoBufferSpace = %d, want 1", got)
	}
}

// newBottleneckNode returns a stack with production TCP settings whose
// non-local traffic is queued for WireGuard.
func newBottleneckNode(b *testing.B, ip netip.Addr) (*stack.Stack, *linkEndpoint) {
	ns := &Impl{}
	ns.atomicIsLocalIPFunc.Store(func(a netip.Addr) bool { return a == ip })
	ns.atomicIsVIPServiceIPFunc.Store(func(netip.Addr) bool { return false })
	ep := newLinkEndpoint(512, 1280, "", groNotSupported, ns.outboundQueueForPacket)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	b.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	cubic := tcpip.CongestionControlOption("cubic")
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &cubic); err != nil {
		b.Fatal(err)
	}
	if err := setTCPBufSizes(s); err != nil {
		b.Fatal(err)
	}
	if err := s.CreateNIC(nicID, ep); err != nil {
		b.Fatal(err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(ip.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		b.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return s, ep
}

// pumpBottleneck moves packets from src's WireGuard queue into dst, at most
// pps packets per second if pps > 0.
func pumpBottleneck(ctx context.Context, src, dst *linkEndpoint, pps int) {
	start := time.Now()
	for n := 1; ; n++ {
		pkt := src.ReadContext(ctx, outboundToWireGuard)
		if pkt == nil {
			return
		}
		dst.DeliverLoopback(pkt)
		if pps > 0 && n%32 == 0 {
			time.Sleep(time.Duration(n)*time.Second/time.Duration(pps) - time.Since(start))
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// BenchmarkTCPQueueBottleneck measures TCP throughput between two stacks when
// the WireGuard-bound queue drains slower than TCP can send, so full queues
// drop packets. Throughput should stay at the link rate.
func BenchmarkTCPQueueBottleneck(b *testing.B) {
	for _, pps := range []int{100_000, 0} {
		for _, streams := range []int{1, 8} {
			b.Run(fmt.Sprintf("pps=%d/streams=%d", pps, streams), func(b *testing.B) {
				ipA, ipB := netip.MustParseAddr("100.64.1.1"), netip.MustParseAddr("100.64.1.2")
				sA, epA := newBottleneckNode(b, ipA)
				sB, epB := newBottleneckNode(b, ipB)
				ctx, cancel := context.WithCancel(context.Background())
				b.Cleanup(cancel)
				go pumpBottleneck(ctx, epA, epB, pps)
				go pumpBottleneck(ctx, epB, epA, 0)
				addr := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(ipB.As4()), Port: 8080}
				ln, err := gonet.ListenTCP(sB, addr, header.IPv4ProtocolNumber)
				if err != nil {
					b.Fatal(err)
				}
				defer ln.Close()
				var conns, sconns []io.ReadWriteCloser
				for range streams {
					c, err := gonet.DialContextTCP(ctx, sA, addr, header.IPv4ProtocolNumber)
					if err != nil {
						b.Fatal(err)
					}
					defer c.Close()
					sc, err := ln.Accept()
					if err != nil {
						b.Fatal(err)
					}
					defer sc.Close()
					conns, sconns = append(conns, c), append(sconns, sc)
				}
				const chunk = 1 << 20
				errc := make(chan error, 2*streams)
				b.SetBytes(int64(streams * chunk))
				for b.Loop() {
					for i := range streams {
						go func() { _, err := io.CopyN(conns[i], zeroReader{}, chunk); errc <- err }()
						go func() { _, err := io.CopyN(io.Discard, sconns[i], chunk); errc <- err }()
					}
					for range 2 * streams {
						if err := <-errc; err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(sA.Stats().TCP.Retransmits.Value())/float64(b.N), "retransmits/op")
				b.ReportMetric(float64(epA.queueFullDroppedTotal())/float64(b.N), "drops/op")
			})
		}
	}
}
