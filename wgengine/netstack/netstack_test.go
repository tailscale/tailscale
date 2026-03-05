// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/metrics"
	"tailscale.com/net/netx"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

// captureTUN is a tun.Device that captures packets written to it.
type captureTUN struct {
	closechan chan struct{}
	ch        chan []byte
}

func newCaptureTUN() *captureTUN {
	return &captureTUN{
		closechan: make(chan struct{}),
		ch:        make(chan []byte, 16),
	}
}

func (t *captureTUN) File() *os.File                { panic("not implemented") }
func (t *captureTUN) Events() <-chan tun.Event       { return make(chan tun.Event) }
func (t *captureTUN) BatchSize() int                 { return 1 }
func (t *captureTUN) MTU() (int, error)              { return 1500, nil }
func (t *captureTUN) Name() (string, error)          { return "CaptureTUN", nil }
func (t *captureTUN) Flush() error                   { return nil }
func (t *captureTUN) IsFakeTun() bool                { return true }
func (t *captureTUN) Close() error                   { close(t.closechan); return nil }
func (t *captureTUN) Read(out [][]byte, sizes []int, offset int) (int, error) {
	<-t.closechan
	return 0, io.EOF
}

func (t *captureTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if offset < len(buf) {
			pkt := make([]byte, len(buf)-offset)
			copy(pkt, buf[offset:])
			select {
			case t.ch <- pkt:
			default:
			}
		}
	}
	return len(bufs), nil
}

// TestInjectInboundLeak tests that injectInbound doesn't leak memory.
// See https://github.com/tailscale/tailscale/issues/3762
func TestInjectInboundLeak(t *testing.T) {
	tunDev := tstun.NewFake()
	dialer := new(tsdial.Dialer)
	logf := func(format string, args ...any) {
		if !t.Failed() {
			t.Logf(format, args...)
		}
	}
	sys := tsd.NewSystem()
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           tunDev,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	sys.Set(eng)
	sys.Set(new(mem.Store))

	tunWrap := sys.Tun.Get()
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lb.Shutdown)

	ns, err := Create(logf, tunWrap, eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.ProcessLocalIPs = true
	if err := ns.Start(lb); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return true })

	pkt := &packet.Parsed{}
	const N = 10_000
	ms0 := getMemStats()
	for range N {
		outcome, _ := ns.injectInbound(pkt, tunWrap, nil)
		if outcome != filter.DropSilently {
			t.Fatalf("got outcome %v; want DropSilently", outcome)
		}
	}
	ms1 := getMemStats()
	if grew := int64(ms1.HeapObjects) - int64(ms0.HeapObjects); grew >= N {
		t.Fatalf("grew by %v (which is too much and >= the %v packets we sent)", grew, N)
	}
}

func getMemStats() (ms runtime.MemStats) {
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return
}

func makeNetstack(tb testing.TB, config func(*Impl)) *Impl {
	tunDev := tstun.NewFake()
	sys := tsd.NewSystem()
	sys.Set(new(mem.Store))
	dialer := new(tsdial.Dialer)
	logf := tstest.WhileTestRunningLogger(tb)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           tunDev,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { eng.Close() })
	sys.Set(eng)

	ns, err := Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { ns.Close() })
	sys.Set(ns)

	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		tb.Fatalf("NewLocalBackend: %v", err)
	}
	tb.Cleanup(lb.Shutdown)

	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return true })
	if config != nil {
		config(ns)
	}
	if err := ns.Start(lb); err != nil {
		tb.Fatalf("Start: %v", err)
	}
	return ns
}

func TestShouldHandlePing(t *testing.T) {
	srcIP := netip.AddrFrom4([4]byte{1, 2, 3, 4})

	t.Run("ICMP4", func(t *testing.T) {
		dst := netip.MustParseAddr("5.6.7.8")
		icmph := packet.ICMP4Header{
			IP4Header: packet.IP4Header{
				IPProto: ipproto.ICMPv4,
				Src:     srcIP,
				Dst:     dst,
			},
			Type: packet.ICMP4EchoRequest,
			Code: packet.ICMP4NoCode,
		}
		_, payload := packet.ICMPEchoPayload(nil)
		icmpPing := packet.Generate(icmph, payload)
		pkt := &packet.Parsed{}
		pkt.Decode(icmpPing)

		impl := makeNetstack(t, func(impl *Impl) {
			impl.ProcessSubnets = true
		})
		pingDst, ok := impl.shouldHandlePing(pkt)
		if !ok {
			t.Errorf("expected shouldHandlePing==true")
		}
		if pingDst != dst {
			t.Errorf("got dst %s; want %s", pingDst, dst)
		}
	})

	t.Run("ICMP6-no-via", func(t *testing.T) {
		dst := netip.MustParseAddr("2a09:8280:1::4169")
		icmph := packet.ICMP6Header{
			IP6Header: packet.IP6Header{
				IPProto: ipproto.ICMPv6,
				Src:     srcIP,
				Dst:     dst,
			},
			Type: packet.ICMP6EchoRequest,
			Code: packet.ICMP6NoCode,
		}
		_, payload := packet.ICMPEchoPayload(nil)
		icmpPing := packet.Generate(icmph, payload)
		pkt := &packet.Parsed{}
		pkt.Decode(icmpPing)

		impl := makeNetstack(t, func(impl *Impl) {
			impl.ProcessSubnets = true
		})
		pingDst, ok := impl.shouldHandlePing(pkt)

		// Expect that we handle this since it's going out onto the
		// network.
		if !ok {
			t.Errorf("expected shouldHandlePing==true")
		}
		if pingDst != dst {
			t.Errorf("got dst %s; want %s", pingDst, dst)
		}
	})

	t.Run("ICMP6-tailscale-addr", func(t *testing.T) {
		dst := netip.MustParseAddr("fd7a:115c:a1e0:ab12::1")
		icmph := packet.ICMP6Header{
			IP6Header: packet.IP6Header{
				IPProto: ipproto.ICMPv6,
				Src:     srcIP,
				Dst:     dst,
			},
			Type: packet.ICMP6EchoRequest,
			Code: packet.ICMP6NoCode,
		}
		_, payload := packet.ICMPEchoPayload(nil)
		icmpPing := packet.Generate(icmph, payload)
		pkt := &packet.Parsed{}
		pkt.Decode(icmpPing)

		impl := makeNetstack(t, func(impl *Impl) {
			impl.ProcessSubnets = true
		})
		_, ok := impl.shouldHandlePing(pkt)

		// We don't handle this because it's a Tailscale IP and not 4via6
		if ok {
			t.Errorf("expected shouldHandlePing==false")
		}
	})

	// Handle pings for 4via6 addresses regardless of ProcessSubnets
	for _, subnets := range []bool{true, false} {
		t.Run("ICMP6-4via6-ProcessSubnets-"+fmt.Sprint(subnets), func(t *testing.T) {
			// The 4via6 route 10.1.1.0/24 siteid 7, and then the IP
			// 10.1.1.9 within that route.
			dst := netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:7:a01:109")
			expectedPingDst := netip.MustParseAddr("10.1.1.9")
			icmph := packet.ICMP6Header{
				IP6Header: packet.IP6Header{
					IPProto: ipproto.ICMPv6,
					Src:     srcIP,
					Dst:     dst,
				},
				Type: packet.ICMP6EchoRequest,
				Code: packet.ICMP6NoCode,
			}
			_, payload := packet.ICMPEchoPayload(nil)
			icmpPing := packet.Generate(icmph, payload)
			pkt := &packet.Parsed{}
			pkt.Decode(icmpPing)

			impl := makeNetstack(t, func(impl *Impl) {
				impl.ProcessSubnets = subnets
			})
			pingDst, ok := impl.shouldHandlePing(pkt)

			// Handled due to being 4via6
			if !ok {
				t.Errorf("expected shouldHandlePing==true")
			} else if pingDst != expectedPingDst {
				t.Errorf("got dst %s; want %s", pingDst, expectedPingDst)
			}
		})
	}
}

// looksLikeATailscaleSelfAddress reports whether addr looks like
// a Tailscale self address, for tests.
func looksLikeATailscaleSelfAddress(addr netip.Addr) bool {
	return addr.Is4() && tsaddr.IsTailscaleIP(addr) ||
		addr.Is6() && tsaddr.Tailscale4To6Range().Contains(addr)
}

func TestShouldProcessInbound(t *testing.T) {
	testCases := []struct {
		name        string
		pkt         *packet.Parsed
		afterStart  func(*Impl) // optional; after Impl.Start is called
		beforeStart func(*Impl) // optional; before Impl.Start is called
		want        bool
		runOnGOOS   string
	}{
		{
			name: "ipv6-via",
			pkt: &packet.Parsed{
				IPVersion: 6,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),

				// $ tailscale debug via 7 10.1.1.9/24
				// fd7a:115c:a1e0:b1a:0:7:a01:109/120
				Dst:      netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:109]:5678"),
				TCPFlags: packet.TCPSyn,
			},
			afterStart: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					// $ tailscale debug via 7 10.1.1.0/24
					// fd7a:115c:a1e0:b1a:0:7:a01:100/120
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:100/120"),
				}
				i.lb.Start(ipn.Options{
					UpdatePrefs: prefs,
				})
				i.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)
			},
			beforeStart: func(i *Impl) {
				// This should be handled even if we're
				// otherwise not processing local IPs or
				// subnets.
				i.ProcessLocalIPs = false
				i.ProcessSubnets = false
			},
			want: true,
		},
		{
			name: "ipv6-via-not-advertised",
			pkt: &packet.Parsed{
				IPVersion: 6,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),

				// $ tailscale debug via 7 10.1.1.9/24
				// fd7a:115c:a1e0:b1a:0:7:a01:109/120
				Dst:      netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:109]:5678"),
				TCPFlags: packet.TCPSyn,
			},
			afterStart: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					// tailscale debug via 7 10.1.2.0/24
					// fd7a:115c:a1e0:b1a:0:7:a01:200/120
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:200/120"),
				}
				i.lb.Start(ipn.Options{
					UpdatePrefs: prefs,
				})
			},
			want: false,
		},
		{
			name: "tailscale-ssh-enabled",
			pkt: &packet.Parsed{
				IPVersion: 4,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),
				Dst:       netip.MustParseAddrPort("100.101.102.104:22"),
				TCPFlags:  packet.TCPSyn,
			},
			afterStart: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.RunSSH = true
				i.lb.Start(ipn.Options{
					UpdatePrefs: prefs,
				})
				i.atomicIsLocalIPFunc.Store(func(addr netip.Addr) bool {
					return addr.String() == "100.101.102.104" // Dst, above
				})
			},
			want:      true,
			runOnGOOS: "linux",
		},
		{
			name: "tailscale-ssh-disabled",
			pkt: &packet.Parsed{
				IPVersion: 4,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),
				Dst:       netip.MustParseAddrPort("100.101.102.104:22"),
				TCPFlags:  packet.TCPSyn,
			},
			afterStart: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.RunSSH = false // default, but to be explicit
				i.lb.Start(ipn.Options{
					UpdatePrefs: prefs,
				})
				i.atomicIsLocalIPFunc.Store(func(addr netip.Addr) bool {
					return addr.String() == "100.101.102.104" // Dst, above
				})
			},
			want: false,
		},
		{
			name: "process-local-ips",
			pkt: &packet.Parsed{
				IPVersion: 4,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),
				Dst:       netip.MustParseAddrPort("100.101.102.104:4567"),
				TCPFlags:  packet.TCPSyn,
			},
			afterStart: func(i *Impl) {
				i.ProcessLocalIPs = true
				i.atomicIsLocalIPFunc.Store(func(addr netip.Addr) bool {
					return addr.String() == "100.101.102.104" // Dst, above
				})
			},
			want: true,
		},
		{
			name: "process-subnets",
			pkt: &packet.Parsed{
				IPVersion: 4,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),
				Dst:       netip.MustParseAddrPort("10.1.2.3:4567"),
				TCPFlags:  packet.TCPSyn,
			},
			beforeStart: func(i *Impl) {
				i.ProcessSubnets = true
			},
			afterStart: func(i *Impl) {
				// For testing purposes, assume all Tailscale
				// IPs are local; the Dst above is something
				// not in that range.
				i.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)
			},
			want: true,
		},
		{
			name: "peerapi-port-subnet-router", // see #6235
			pkt: &packet.Parsed{
				IPVersion: 4,
				IPProto:   ipproto.TCP,
				Src:       netip.MustParseAddrPort("100.101.102.103:1234"),
				Dst:       netip.MustParseAddrPort("10.0.0.23:5555"),
				TCPFlags:  packet.TCPSyn,
			},
			beforeStart: func(i *Impl) {
				// As if we were running on Linux where netstack isn't used.
				i.ProcessSubnets = false
				i.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return false })
			},
			afterStart: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.1/24"),
				}
				i.lb.Start(ipn.Options{
					UpdatePrefs: prefs,
				})

				// Set the PeerAPI port to the Dst port above.
				i.peerapiPort4Atomic.Store(5555)
				i.peerapiPort6Atomic.Store(5555)
			},
			want: false,
		},

		// TODO(andrew): test PeerAPI
		// TODO(andrew): test TCP packets without the SYN flag set
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.runOnGOOS != "" && runtime.GOOS != tc.runOnGOOS {
				t.Skipf("skipping on GOOS=%v", runtime.GOOS)
			}
			impl := makeNetstack(t, tc.beforeStart)
			if tc.afterStart != nil {
				tc.afterStart(impl)
			}

			got := impl.shouldProcessInbound(tc.pkt, nil)
			if got != tc.want {
				t.Errorf("got shouldProcessInbound()=%v; want %v", got, tc.want)
			} else {
				t.Logf("OK: shouldProcessInbound() = %v", got)
			}
		})
	}
}

func tcp4syn(tb testing.TB, src, dst netip.Addr, sport, dport uint16) []byte {
	ip := header.IPv4(make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize))
	ip.Encode(&header.IPv4Fields{
		Protocol:    uint8(header.TCPProtocolNumber),
		TotalLength: header.IPv4MinimumSize + header.TCPMinimumSize,
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4Slice(src.AsSlice()),
		DstAddr:     tcpip.AddrFrom4Slice(dst.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	if !ip.IsChecksumValid() {
		tb.Fatal("test broken; packet has incorrect IP checksum")
	}

	tcp := header.TCP(ip[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    sport,
		DstPort:    dport,
		SeqNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
		Checksum:   0,
	})
	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFrom4Slice(src.AsSlice()),
		tcpip.AddrFrom4Slice(dst.AsSlice()),
		uint16(header.TCPMinimumSize),
	)
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	if !tcp.IsChecksumValid(tcpip.AddrFrom4Slice(src.AsSlice()), tcpip.AddrFrom4Slice(dst.AsSlice()), 0, 0) {
		tb.Fatal("test broken; packet has incorrect TCP checksum")
	}

	return ip
}

// makeHangDialer returns a dialer that notifies the returned channel when a
// connection is dialed and then hangs until the test finishes.
func makeHangDialer(tb testing.TB) (netx.DialFunc, chan struct{}) {
	done := make(chan struct{})
	tb.Cleanup(func() {
		close(done)
	})

	gotConn := make(chan struct{}, 1)
	fn := func(ctx context.Context, network, address string) (net.Conn, error) {
		// Signal that we have a new connection
		tb.Logf("hangDialer: called with network=%q address=%q", network, address)
		select {
		case gotConn <- struct{}{}:
		default:
		}

		// Hang until the test is done.
		select {
		case <-ctx.Done():
			tb.Logf("context done")
		case <-done:
			tb.Logf("function completed")
		}
		return nil, fmt.Errorf("canceled")
	}
	return fn, gotConn
}

// TestTCPForwardLimits verifies that the limits on the TCP forwarder work in a
// success case (i.e. when we don't hit the limit).
func TestTCPForwardLimits(t *testing.T) {
	envknob.Setenv("TS_DEBUG_NETSTACK", "true")
	impl := makeNetstack(t, func(impl *Impl) {
		impl.ProcessSubnets = true
	})

	dialFn, gotConn := makeHangDialer(t)
	impl.forwardDialFunc = dialFn

	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{
		// This is the TEST-NET-1 IP block for use in documentation,
		// and should never actually be routable.
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	impl.lb.Start(ipn.Options{
		UpdatePrefs: prefs,
	})
	impl.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)

	// Inject an "outbound" packet that's going to an IP address that times
	// out. We need to re-parse from a byte slice so that the internal
	// buffer in the packet.Parsed type is filled out.
	client := netip.MustParseAddr("100.101.102.103")
	destAddr := netip.MustParseAddr("192.0.2.1")
	pkt := tcp4syn(t, client, destAddr, 1234, 4567)
	var parsed packet.Parsed
	parsed.Decode(pkt)

	// When injecting this packet, we want the outcome to be "drop
	// silently", which indicates that netstack is processing the
	// packet and not delivering it to the host system.
	if resp, _ := impl.injectInbound(&parsed, impl.tundev, nil); resp != filter.DropSilently {
		t.Errorf("got filter outcome %v, want filter.DropSilently", resp)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Wait until we have an in-flight outgoing connection.
	select {
	case <-ctx.Done():
		t.Fatalf("timed out waiting for connection")
	case <-gotConn:
		t.Logf("got connection in progress")
	}

	// Inject another packet, which will be deduplicated and thus not
	// increment our counter.
	parsed.Decode(pkt)
	if resp, _ := impl.injectInbound(&parsed, impl.tundev, nil); resp != filter.DropSilently {
		t.Errorf("got filter outcome %v, want filter.DropSilently", resp)
	}

	// Verify that we now have a single in-flight address in our map.
	impl.mu.Lock()
	inFlight := maps.Clone(impl.connsInFlightByClient)
	impl.mu.Unlock()

	if got, ok := inFlight[client]; !ok || got != 1 {
		t.Errorf("expected 1 in-flight connection for %v, got: %v", client, inFlight)
	}

	// Get the expvar statistics and verify that we're exporting the
	// correct metric.
	metrics := impl.ExpVar().(*metrics.Set)

	const metricName = "gauge_tcp_forward_in_flight"
	if v := metrics.Get(metricName).String(); v != "1" {
		t.Errorf("got metric %q=%s, want 1", metricName, v)
	}
}

// TestTCPForwardLimits_PerClient verifies that the per-client limit for TCP
// forwarding works.
func TestTCPForwardLimits_PerClient(t *testing.T) {
	envknob.Setenv("TS_DEBUG_NETSTACK", "true")

	// Set our test override limits during this test.
	tstest.Replace(t, &maxInFlightConnectionAttemptsForTest, 2)
	tstest.Replace(t, &maxInFlightConnectionAttemptsPerClientForTest, 1)

	impl := makeNetstack(t, func(impl *Impl) {
		impl.ProcessSubnets = true
	})

	dialFn, gotConn := makeHangDialer(t)
	impl.forwardDialFunc = dialFn

	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{
		// This is the TEST-NET-1 IP block for use in documentation,
		// and should never actually be routable.
		netip.MustParsePrefix("192.0.2.0/24"),
	}
	impl.lb.Start(ipn.Options{
		UpdatePrefs: prefs,
	})
	impl.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)

	// Inject an "outbound" packet that's going to an IP address that times
	// out. We need to re-parse from a byte slice so that the internal
	// buffer in the packet.Parsed type is filled out.
	client := netip.MustParseAddr("100.101.102.103")
	destAddr := netip.MustParseAddr("192.0.2.1")

	// Helpers
	var port uint16 = 1234
	mustInjectPacket := func() {
		pkt := tcp4syn(t, client, destAddr, port, 4567)
		port++ // to avoid deduplication based on endpoint

		var parsed packet.Parsed
		parsed.Decode(pkt)

		// When injecting this packet, we want the outcome to be "drop
		// silently", which indicates that netstack is processing the
		// packet and not delivering it to the host system.
		if resp, _ := impl.injectInbound(&parsed, impl.tundev, nil); resp != filter.DropSilently {
			t.Fatalf("got filter outcome %v, want filter.DropSilently", resp)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	waitPacket := func() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for connection")
		case <-gotConn:
			t.Logf("got connection in progress")
		}
	}

	// Inject the packet to start the TCP forward and wait until we have an
	// in-flight outgoing connection.
	mustInjectPacket()
	waitPacket()

	// Verify that we now have a single in-flight address in our map.
	impl.mu.Lock()
	inFlight := maps.Clone(impl.connsInFlightByClient)
	impl.mu.Unlock()

	if got, ok := inFlight[client]; !ok || got != 1 {
		t.Errorf("expected 1 in-flight connection for %v, got: %v", client, inFlight)
	}

	metrics := impl.ExpVar().(*metrics.Set)

	// One client should have reached the limit at this point.
	if v := metrics.Get("gauge_tcp_forward_in_flight_per_client_limit_reached").String(); v != "1" {
		t.Errorf("got limit reached expvar metric=%s, want 1", v)
	}

	// Inject another packet, and verify that we've incremented our
	// "dropped" metrics since this will have been dropped.
	mustInjectPacket()

	// expvar metric
	const metricName = "counter_tcp_forward_max_in_flight_per_client_drop"
	if v := metrics.Get(metricName).String(); v != "1" {
		t.Errorf("got expvar metric %q=%s, want 1", metricName, v)
	}

	// client metric
	if v := metricPerClientForwardLimit.Value(); v != 1 {
		t.Errorf("got clientmetric limit metric=%d, want 1", v)
	}
}

// TestHandleLocalPackets tests the handleLocalPackets function, ensuring that
// we are properly deciding to handle packets that are destined for "local"
// IPs–addresses that are either for this node, or that it is responsible for.
//
// See, e.g. #11304
func TestHandleLocalPackets(t *testing.T) {
	var (
		selfIP4 = netip.MustParseAddr("100.64.1.2")
		selfIP6 = netip.MustParseAddr("fd7a:115c:a1e0::123")
	)

	impl := makeNetstack(t, func(impl *Impl) {
		impl.ProcessSubnets = false
		impl.ProcessLocalIPs = false
		impl.atomicIsLocalIPFunc.Store(func(addr netip.Addr) bool {
			return addr == selfIP4 || addr == selfIP6
		})
	})

	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = []netip.Prefix{
		// $ tailscale debug via 7 10.1.1.0/24
		// fd7a:115c:a1e0:b1a:0:7:a01:100/120
		netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:100/120"),
	}
	prefs.AdvertiseServices = []string{"svc:test-service"}
	_, err := impl.lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs:                *prefs,
		AdvertiseRoutesSet:   true,
		AdvertiseServicesSet: true,
	})
	if err != nil {
		t.Fatalf("EditPrefs: %v", err)
	}
	IPServiceMap := netmap.IPServiceMappings{
		netip.MustParseAddr("100.99.55.111"):        "svc:test-service",
		netip.MustParseAddr("fd7a:115c:a1e0::abcd"): "svc:test-service",
	}
	impl.lb.SetIPServiceMappingsForTest(IPServiceMap)

	t.Run("ShouldHandleServiceIP", func(t *testing.T) {
		pkt := &packet.Parsed{
			IPVersion: 4,
			IPProto:   ipproto.TCP,
			Src:       netip.MustParseAddrPort("127.0.0.1:9999"),
			Dst:       netip.MustParseAddrPort("100.100.100.100:53"),
			TCPFlags:  packet.TCPSyn,
		}
		resp, _ := impl.handleLocalPackets(pkt, impl.tundev, nil)
		if resp != filter.DropSilently {
			t.Errorf("got filter outcome %v, want filter.DropSilently", resp)
		}
	})
	t.Run("ShouldHandle4via6", func(t *testing.T) {
		pkt := &packet.Parsed{
			IPVersion: 6,
			IPProto:   ipproto.TCP,
			Src:       netip.MustParseAddrPort("[::1]:1234"),

			// This is an IP in the above 4via6 subnet that this node handles.
			//    $ tailscale debug via 7 10.1.1.9/24
			//    fd7a:115c:a1e0:b1a:0:7:a01:109/120
			Dst:      netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:109]:5678"),
			TCPFlags: packet.TCPSyn,
		}
		resp, _ := impl.handleLocalPackets(pkt, impl.tundev, nil)

		// DropSilently is the outcome we expected, since we actually
		// handled this packet by injecting it into netstack, which
		// will handle creating the TCP forwarder. We drop it so we
		// don't process the packet outside of netstack.
		if resp != filter.DropSilently {
			t.Errorf("got filter outcome %v, want filter.DropSilently", resp)
		}
	})
	t.Run("ShouldHandleLocalTailscaleServices", func(t *testing.T) {
		pkt := &packet.Parsed{
			IPVersion: 4,
			IPProto:   ipproto.TCP,
			Src:       netip.MustParseAddrPort("127.0.0.1:9999"),
			Dst:       netip.MustParseAddrPort("100.99.55.111:80"),
			TCPFlags:  packet.TCPSyn,
		}
		resp, _ := impl.handleLocalPackets(pkt, impl.tundev, nil)
		if resp != filter.DropSilently {
			t.Errorf("got filter outcome %v, want filter.DropSilently", resp)
		}
	})
	t.Run("OtherNonHandled", func(t *testing.T) {
		pkt := &packet.Parsed{
			IPVersion: 6,
			IPProto:   ipproto.TCP,
			Src:       netip.MustParseAddrPort("[::1]:1234"),

			// This IP is *not* in the above 4via6 route
			//    $ tailscale debug via 99 10.1.1.9/24
			//    fd7a:115c:a1e0:b1a:0:63:a01:109/120
			Dst:      netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:63:a01:109]:5678"),
			TCPFlags: packet.TCPSyn,
		}
		resp, _ := impl.handleLocalPackets(pkt, impl.tundev, nil)

		// Accept means that handleLocalPackets does not handle this
		// packet, we "accept" it to continue further processing,
		// instead of dropping because it was already handled.
		if resp != filter.Accept {
			t.Errorf("got filter outcome %v, want filter.Accept", resp)
		}
	})
}

func TestShouldSendToHost(t *testing.T) {
	var (
		selfIP4             = netip.MustParseAddr("100.64.1.2")
		selfIP6             = netip.MustParseAddr("fd7a:115c:a1e0::123")
		tailscaleServiceIP4 = netip.MustParseAddr("100.99.55.111")
		tailscaleServiceIP6 = netip.MustParseAddr("fd7a:115c:a1e0::abcd")
	)

	makeTestNetstack := func(tb testing.TB) *Impl {
		impl := makeNetstack(tb, func(impl *Impl) {
			impl.ProcessSubnets = false
			impl.ProcessLocalIPs = false
			impl.atomicIsLocalIPFunc.Store(func(addr netip.Addr) bool {
				return addr == selfIP4 || addr == selfIP6
			})
			impl.atomicIsVIPServiceIPFunc.Store(func(addr netip.Addr) bool {
				return addr == tailscaleServiceIP4 || addr == tailscaleServiceIP6
			})
		})

		prefs := ipn.NewPrefs()
		prefs.AdvertiseRoutes = []netip.Prefix{
			// $ tailscale debug via 7 10.1.1.0/24
			// fd7a:115c:a1e0:b1a:0:7:a01:100/120
			netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:100/120"),
		}
		_, err := impl.lb.EditPrefs(&ipn.MaskedPrefs{
			Prefs:              *prefs,
			AdvertiseRoutesSet: true,
		})
		if err != nil {
			tb.Fatalf("EditPrefs: %v", err)
		}
		return impl
	}

	testCases := []struct {
		name     string
		src, dst netip.AddrPort
		want     bool
	}{
		// Reply from service IP to localhost should be sent to host,
		// not over WireGuard.
		{
			name: "from_service_ip_to_localhost",
			src:  netip.AddrPortFrom(serviceIP, 53),
			dst:  netip.MustParseAddrPort("127.0.0.1:9999"),
			want: true,
		},
		{
			name: "from_service_ip_to_localhost_v6",
			src:  netip.AddrPortFrom(serviceIPv6, 53),
			dst:  netip.MustParseAddrPort("[::1]:9999"),
			want: true,
		},
		// A reply from the local IP to a remote host isn't sent to the
		// host, but rather over WireGuard.
		{
			name: "local_ip_to_remote",
			src:  netip.AddrPortFrom(selfIP4, 12345),
			dst:  netip.MustParseAddrPort("100.64.99.88:7777"),
			want: false,
		},
		{
			name: "local_ip_to_remote_v6",
			src:  netip.AddrPortFrom(selfIP6, 12345),
			dst:  netip.MustParseAddrPort("[fd7a:115:a1e0::99]:7777"),
			want: false,
		},
		// A reply from a 4via6 address to a remote host isn't sent to
		// the local host, but rather over WireGuard. See:
		//     https://github.com/tailscale/tailscale/issues/12448
		{
			name: "4via6_to_remote",

			// $ tailscale debug via 7 10.1.1.99/24
			// fd7a:115c:a1e0:b1a:0:7:a01:163/120
			src:  netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:163]:12345"),
			dst:  netip.MustParseAddrPort("[fd7a:115:a1e0::99]:7777"),
			want: false,
		},
		// However, a reply from a 4via6 address to the local Tailscale
		// IP for this host *is* sent to the local host. See:
		//     https://github.com/tailscale/tailscale/issues/11304
		{
			name: "4via6_to_local",

			// $ tailscale debug via 7 10.1.1.99/24
			// fd7a:115c:a1e0:b1a:0:7:a01:163/120
			src:  netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:7:a01:163]:12345"),
			dst:  netip.AddrPortFrom(selfIP6, 7777),
			want: true,
		},
		// Traffic from a 4via6 address that we're not handling to
		// either the local Tailscale IP or a remote host is sent
		// outbound.
		//
		// In most cases, we won't see this type of traffic in the
		// shouldSendToHost function, but let's confirm.
		{
			name: "other_4via6_to_local",

			// $ tailscale debug via 4444 10.1.1.88/24
			// fd7a:115c:a1e0:b1a:0:7:a01:163/120
			src:  netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:115c:a01:158]:12345"),
			dst:  netip.AddrPortFrom(selfIP6, 7777),
			want: false,
		},
		{
			name: "other_4via6_to_remote",

			// $ tailscale debug via 4444 10.1.1.88/24
			// fd7a:115c:a1e0:b1a:0:7:a01:163/120
			src:  netip.MustParseAddrPort("[fd7a:115c:a1e0:b1a:0:115c:a01:158]:12345"),
			dst:  netip.MustParseAddrPort("[fd7a:115:a1e0::99]:7777"),
			want: false,
		},
		// After accessing the Tailscale service from host, replies from Tailscale Service IPs
		// to the local Tailscale IPs should be sent to the host.
		{
			name: "from_service_ip_to_local_ip",
			src:  netip.AddrPortFrom(tailscaleServiceIP4, 80),
			dst:  netip.AddrPortFrom(selfIP4, 12345),
			want: true,
		},
		{
			name: "from_service_ip_to_local_ip_v6",
			src:  netip.AddrPortFrom(tailscaleServiceIP6, 80),
			dst:  netip.AddrPortFrom(selfIP6, 12345),
			want: true,
		},
		// Traffic from remote IPs to Tailscale Service IPs should be sent over WireGuard.
		{
			name: "from_service_ip_to_remote",
			src:  netip.AddrPortFrom(tailscaleServiceIP4, 80),
			dst:  netip.MustParseAddrPort("173.201.32.56:54321"),
			want: false,
		},
		{
			name: "from_service_ip_to_remote_v6",
			src:  netip.AddrPortFrom(tailscaleServiceIP6, 80),
			dst:  netip.MustParseAddrPort("[2001:4860:4860::8888]:54321"),
			want: false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			var pkt *stack.PacketBuffer
			if tt.src.Addr().Is4() {
				pkt = makeUDP4PacketBuffer(tt.src, tt.dst)
			} else {
				pkt = makeUDP6PacketBuffer(tt.src, tt.dst)
			}

			ns := makeTestNetstack(t)
			if got := ns.shouldSendToHost(pkt); got != tt.want {
				t.Errorf("shouldSendToHost returned %v, want %v", got, tt.want)
			}
		})
	}
}

func makeUDP4PacketBuffer(src, dst netip.AddrPort) *stack.PacketBuffer {
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		panic("src and dst must be IPv4")
	}

	data := []byte("hello world\n")

	packetLen := header.IPv4MinimumSize + header.UDPMinimumSize
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: packetLen,
		Payload:            buffer.MakeWithData(data),
	})

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = header.UDPProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  length,
	})

	// Add IP header
	ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(packetLen),
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(dst.Addr().As4()),
		Checksum:    0,
	})

	return pkt
}

func makeUDP6PacketBuffer(src, dst netip.AddrPort) *stack.PacketBuffer {
	if !src.Addr().Is6() || !dst.Addr().Is6() {
		panic("src and dst must be IPv6")
	}
	data := []byte("hello world\n")

	packetLen := header.IPv6MinimumSize + header.UDPMinimumSize
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: packetLen,
		Payload:            buffer.MakeWithData(data),
	})

	srcAddr := tcpip.AddrFrom16(src.Addr().As16())
	dstAddr := tcpip.AddrFrom16(dst.Addr().As16())

	// Add IP header
	ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	ipHdr.Encode(&header.IPv6Fields{
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
		PayloadLength:     uint16(header.UDPMinimumSize + len(data)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
	})

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = header.UDPProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  length,
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, uint16(len(udp)))
	udp.SetChecksum(^udp.CalculateChecksum(xsum))

	return pkt
}

// udp4packet constructs a raw IPv4+UDP packet with the given addresses, ports,
// and payload, suitable for injecting via injectInbound.
func udp4packet(tb testing.TB, src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	tb.Helper()
	totalLen := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	buf := make([]byte, totalLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		Protocol:    uint8(header.UDPProtocolNumber),
		TotalLength: uint16(totalLen),
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4Slice(src.AsSlice()),
		DstAddr:     tcpip.AddrFrom4Slice(dst.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udpHdr := header.UDP(buf[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: sport,
		DstPort: dport,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(buf[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	// Compute UDP checksum using tun.PseudoHeaderChecksum + tun.Checksum
	// over the full UDP portion (header + payload), which matches how
	// RXChecksumOffload validates packets.
	udpHdr.SetChecksum(0)
	pseudo := tun.PseudoHeaderChecksum(
		uint8(header.UDPProtocolNumber),
		src.AsSlice(), dst.AsSlice(),
		uint16(len(buf)-header.IPv4MinimumSize),
	)
	udpHdr.SetChecksum(^tun.Checksum(buf[header.IPv4MinimumSize:], pseudo))

	return buf
}

// udp6packet constructs a raw IPv6+UDP packet with the given addresses, ports,
// and payload, suitable for injecting via injectInbound.
func udp6packet(tb testing.TB, src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	tb.Helper()
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.IPv6MinimumSize + udpLen
	buf := make([]byte, totalLen)

	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(src.As16()),
		DstAddr:           tcpip.AddrFrom16(dst.As16()),
	})

	udpHdr := header.UDP(buf[header.IPv6MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: sport,
		DstPort: dport,
		Length:  uint16(udpLen),
	})
	copy(buf[header.IPv6MinimumSize+header.UDPMinimumSize:], payload)

	// Compute UDP checksum (mandatory for IPv6).
	udpHdr.SetChecksum(0)
	src16, dst16 := src.As16(), dst.As16()
	pseudo := tun.PseudoHeaderChecksum(
		uint8(header.UDPProtocolNumber),
		src16[:], dst16[:],
		uint16(udpLen),
	)
	udpHdr.SetChecksum(^tun.Checksum(buf[header.IPv6MinimumSize:], pseudo))

	return buf
}

// makeNetstackForUDPInjectionTest creates a netstack instance with a
// captureTUN for testing forwardUDPViaInjection. It sets ProcessSubnets=true,
// enables TS_DEBUG_NETSTACK_UDP_RAW, and advertises the given routes.
func makeNetstackForUDPInjectionTest(t *testing.T, routes []netip.Prefix) (*Impl, *captureTUN) {
	t.Helper()

	envknob.Setenv("TS_DEBUG_NETSTACK", "true")
	envknob.Setenv("TS_DEBUG_NETSTACK_UDP_RAW", "true")
	t.Cleanup(func() {
		envknob.Setenv("TS_DEBUG_NETSTACK_UDP_RAW", "")
	})

	capTUN := newCaptureTUN()
	sys := tsd.NewSystem()
	sys.Set(new(mem.Store))
	dialer := new(tsdial.Dialer)
	logf := tstest.WhileTestRunningLogger(t)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:           capTUN,
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		EventBus:      sys.Bus.Get(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })
	sys.Set(eng)

	ns, err := Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	sys.Set(ns)
	ns.ProcessSubnets = true

	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(lb.Shutdown)

	if err := ns.Start(lb); err != nil {
		t.Fatalf("Start: %v", err)
	}

	prefs := ipn.NewPrefs()
	prefs.AdvertiseRoutes = routes
	lb.Start(ipn.Options{
		UpdatePrefs: prefs,
	})
	ns.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)

	return ns, capTUN
}

// testUDPInjection injects a UDP packet into netstack and verifies that the
// packet written to the tun device preserves the original source/destination
// IPs, ports, and payload.
func testUDPInjection(t *testing.T, ns *Impl, capTUN *captureTUN, pkt []byte, wantIPVersion int, srcAddr, dstAddr netip.Addr, srcPort, dstPort uint16, payload []byte) {
	t.Helper()

	var parsed packet.Parsed
	parsed.Decode(pkt)

	if resp, _ := ns.injectInbound(&parsed, ns.tundev, nil); resp != filter.DropSilently {
		t.Fatalf("got filter outcome %v, want filter.DropSilently", resp)
	}

	select {
	case gotPkt := <-capTUN.ch:
		var got packet.Parsed
		got.Decode(gotPkt)
		if got.IPVersion != uint8(wantIPVersion) {
			t.Fatalf("IP version = %d, want %d", got.IPVersion, wantIPVersion)
		}
		if got.IPProto != ipproto.UDP {
			t.Fatalf("IP proto = %v, want UDP", got.IPProto)
		}
		if got.Src.Addr() != srcAddr {
			t.Errorf("source IP = %v, want %v", got.Src.Addr(), srcAddr)
		}
		if got.Dst.Addr() != dstAddr {
			t.Errorf("dest IP = %v, want %v", got.Dst.Addr(), dstAddr)
		}
		if got.Src.Port() != srcPort {
			t.Errorf("source port = %d, want %d", got.Src.Port(), srcPort)
		}
		if got.Dst.Port() != dstPort {
			t.Errorf("dest port = %d, want %d", got.Dst.Port(), dstPort)
		}
		if gotPayload := got.Payload(); string(gotPayload) != string(payload) {
			t.Errorf("payload = %q, want %q", gotPayload, payload)
		}
		t.Logf("OK: captured packet %v:%d -> %v:%d (%d bytes payload)",
			got.Src.Addr(), got.Src.Port(), got.Dst.Addr(), got.Dst.Port(), len(got.Payload()))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for injected packet on tun device")
	}
}

// TestForwardUDPViaInjection verifies that when TS_DEBUG_NETSTACK_UDP_RAW is
// set, subnet-routed UDP packets are forwarded by injecting raw IP packets
// into the tun device, preserving the original source IP address.
func TestForwardUDPViaInjection(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ns, capTUN := makeNetstackForUDPInjectionTest(t, []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"),
		})
		srcAddr := netip.MustParseAddr("100.101.102.103")
		dstAddr := netip.MustParseAddr("192.0.2.1")
		payload := []byte("test-radius-payload")
		pkt := udp4packet(t, srcAddr, dstAddr, 1812, 5678, payload)
		testUDPInjection(t, ns, capTUN, pkt, 4, srcAddr, dstAddr, 1812, 5678, payload)
	})

	t.Run("IPv6", func(t *testing.T) {
		ns, capTUN := makeNetstackForUDPInjectionTest(t, []netip.Prefix{
			netip.MustParsePrefix("2001:db8::/32"),
		})
		srcAddr := netip.MustParseAddr("fd7a:115c:a1e0::1")
		dstAddr := netip.MustParseAddr("2001:db8::1")
		payload := []byte("test-radius-payload-v6")
		pkt := udp6packet(t, srcAddr, dstAddr, 1812, 5678, payload)
		testUDPInjection(t, ns, capTUN, pkt, 6, srcAddr, dstAddr, 1812, 5678, payload)
	})
}
