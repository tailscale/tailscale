// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// TestTCPThroughput measures TCP throughput through gvisor's netstack with
// different simulated network conditions. It uses synctest for simulated time
// so high-latency transfers complete nearly instantly in wall-clock time.
func TestTCPThroughput(t *testing.T) {
	type testCase struct {
		name    string
		cc1     string        // congestion control for node 1
		cc2     string        // congestion control for node 2
		latency time.Duration // one-way network latency
		lossRate float64      // packet loss rate [0, 1)
		size    int64         // bytes to transfer
		bufSize int           // TCP send/receive buffer size
	}

	// Build test grid: all combinations of (cc, latency, loss, bufSize).
	ccs := []string{"reno", "cubic", "bbr"}
	latencies := []struct {
		name string
		d    time.Duration
	}{
		{"1ms", 1 * time.Millisecond},    // ~2ms RTT (same datacenter)
		{"75ms", 75 * time.Millisecond},   // ~150ms RTT (US West <-> EU)
		{"140ms", 140 * time.Millisecond}, // ~280ms RTT (US West <-> SE Asia)
	}
	lossRates := []struct {
		name string
		rate float64
	}{
		{"loss0", 0},
		{"loss1", 0.01},
	}
	bufSizes := []struct {
		name string
		size int // bytes
	}{
		{"buf1M", 1 << 20},  // 1 MiB (close to production defaults)
		{"buf8M", 8 << 20},  // 8 MiB
	}
	const size = 100 << 20 // 100 MiB

	var tests []testCase
	for _, lat := range latencies {
		for _, cc := range ccs {
			for _, loss := range lossRates {
				for _, buf := range bufSizes {
					name := cc + "_" + cc + "_" + lat.name + "_" + loss.name + "_" + buf.name + "_100MiB"
					tests = append(tests, testCase{
						name:     name,
						cc1:      cc,
						cc2:      cc,
						latency:  lat.d,
						lossRate: loss.rate,
						size:     size,
						bufSize:  buf.size,
					})
				}
			}
		}
	}

	var runCounter atomic.Uint64

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := runCounter.Add(1)
			t.Logf("seed=%d", seed)
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())

				ip1 := netip.MustParseAddr("10.0.0.1")
				ip2 := netip.MustParseAddr("10.0.0.2")

				stack1, ep1 := newThroughputStack(t, ip1, tt.cc1, tt.bufSize)
				stack2, ep2 := newThroughputStack(t, ip2, tt.cc2, tt.bufSize)
				defer func() {
					cancel()
					ep1.Close()
					ep2.Close()
					stack1.Close()
					stack2.Close()
					stack1.Wait()
					stack2.Wait()
				}()

				// Wire up bidirectional packet forwarding with
				// different PRNG seeds per direction and per -count run.
				go forwardPackets(ctx, ep1, ep2, tt.latency, tt.lossRate, seed, 0)
				go forwardPackets(ctx, ep2, ep1, tt.latency, tt.lossRate, seed, 1)

				// Listen on stack2.
				listener, err := gonet.ListenTCP(stack2, tcpip.FullAddress{
					Addr: tcpip.AddrFromSlice(ip2.AsSlice()),
					Port: 80,
				}, ipv4.ProtocolNumber)
				if err != nil {
					t.Fatalf("ListenTCP: %v", err)
				}
				defer listener.Close()

				// Server: accept one connection and drain all data.
				type serverResult struct {
					n   int64
					err error
				}
				serverDone := make(chan serverResult, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						serverDone <- serverResult{0, err}
						return
					}
					defer conn.Close()
					n, err := io.Copy(io.Discard, conn)
					serverDone <- serverResult{n, err}
				}()

				// Client: dial from stack1 to stack2.
				conn, err := gonet.DialContextTCP(ctx, stack1, tcpip.FullAddress{
					Addr: tcpip.AddrFromSlice(ip2.AsSlice()),
					Port: 80,
				}, ipv4.ProtocolNumber)
				if err != nil {
					t.Fatalf("DialContextTCP: %v", err)
				}

				start := time.Now()
				written, err := io.CopyN(conn, zeroReader{}, tt.size)
				if err != nil {
					t.Fatalf("writing data: %v (wrote %d of %d)", err, written, tt.size)
				}
				conn.CloseWrite()

				result := <-serverDone
				elapsed := time.Since(start)

				if result.err != nil {
					t.Fatalf("server: %v", result.err)
				}
				if result.n != tt.size {
					t.Fatalf("server received %d bytes, want %d", result.n, tt.size)
				}

				mibps := float64(tt.size) / (1 << 20) / elapsed.Seconds()
				t.Logf("transferred %d MiB in %v (simulated): %.2f MiB/s",
					tt.size>>20, elapsed, mibps)
			})
		})
	}
}

// zeroReader is an io.Reader that produces zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// newThroughputStack creates a minimal gvisor network stack with a single NIC,
// the given IP address, and the specified TCP congestion control algorithm.
// The caller is responsible for calling Close/Wait on the returned stack.
func newThroughputStack(t *testing.T, addr netip.Addr, cc string, bufSize int) (*stack.Stack, *linkEndpoint) {
	t.Helper()

	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	sackOpt := tcpip.TCPSACKEnabled(true)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		t.Fatalf("enabling SACK: %v", err)
	}

	recoveryOpt := tcpip.TCPRecovery(0)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &recoveryOpt); err != nil {
		t.Fatalf("disabling RACK: %v", err)
	}

	ccOpt := tcpip.CongestionControlOption(cc)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt); err != nil {
		t.Fatalf("setting congestion control to %q: %v", cc, err)
	}

	// Disable the initial receive window clamp so the window can grow freely.
	clampOpt := tcpip.TCPInitialRcvWndClampOption(false)
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &clampOpt); err != nil {
		t.Fatalf("setting TCPInitialRcvWndClampOption: %v", err)
	}

	rxBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: bufSize, Max: bufSize}
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &rxBufOpt); err != nil {
		t.Fatalf("setting TCP RX buf size: %v", err)
	}
	txBufOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: bufSize, Max: bufSize}
	if err := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &txBufOpt); err != nil {
		t.Fatalf("setting TCP TX buf size: %v", err)
	}

	const mtu = 1500
	ep := newLinkEndpoint(4096, mtu, "", groNotSupported)

	const testNICID = 1
	if err := ipstack.CreateNIC(testNICID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	ipstack.SetPromiscuousMode(testNICID, true)

	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: 24,
		},
	}
	if err := ipstack.AddProtocolAddress(testNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%v): %v", addr, err)
	}

	ipv4Subnet, _ := tcpip.NewSubnet(
		tcpip.AddrFromSlice(make([]byte, 4)),
		tcpip.MaskFromBytes(make([]byte, 4)),
	)
	ipstack.SetRouteTable([]tcpip.Route{{
		Destination: ipv4Subnet,
		NIC:         testNICID,
	}})

	return ipstack, ep
}

// forwardPackets reads outbound packets from src and delivers them to dst,
// simulating network latency and packet loss. For non-zero latency,
// time.AfterFunc schedules future delivery using synctest's simulated clock.
// Each successive packet gets an additional 1µs of delay to simulate link
// serialization delay, preventing gvisor's TCP from misinterpreting batch
// delivery as packet loss.
func forwardPackets(ctx context.Context, src, dst *linkEndpoint, latency time.Duration, lossRate float64, seed uint64, direction uint64) {
	rng := rand.New(rand.NewPCG(seed, direction))
	var seq int64
	for {
		pkt := src.ReadContext(ctx)
		if pkt == nil {
			return
		}

		// Serialize the packet to raw bytes for re-injection.
		view := stack.PayloadSince(pkt.NetworkHeader())
		raw := slices.Clone(view.AsSlice())
		view.Release()
		proto := pkt.NetworkProtocolNumber
		pkt.DecRef()

		if lossRate > 0 && rng.Float64() < lossRate {
			continue
		}

		// Add per-packet serialization delay (1µs) to simulate realistic
		// link behavior. Without this, all segments in a batch arrive at
		// the exact same simulated instant, which causes gvisor's TCP
		// receiver to generate spurious duplicate ACKs and trigger false
		// loss detection.
		seq++
		d := latency + time.Duration(seq)*time.Microsecond
		time.AfterFunc(d, func() {
			deliverPacket(dst, raw, proto)
		})
	}
}

// deliverPacket injects a raw IP packet into the given link endpoint
// as if it arrived from the network.
func deliverPacket(ep *linkEndpoint, raw []byte, proto tcpip.NetworkProtocolNumber) {
	ep.mu.RLock()
	d := ep.dispatcher
	ep.mu.RUnlock()
	if d == nil {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	pkt.NetworkProtocolNumber = proto
	pkt.RXChecksumValidated = true
	d.DeliverNetworkPacket(proto, pkt)
	pkt.DecRef()
}

