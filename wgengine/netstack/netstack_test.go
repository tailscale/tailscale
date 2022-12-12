// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netstack

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

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
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:    tunDev,
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ig, ok := eng.(wgengine.InternalsGetter)
	if !ok {
		t.Fatal("not an InternalsGetter")
	}
	tunWrap, magicSock, dns, ok := ig.GetInternals()
	if !ok {
		t.Fatal("failed to get internals")
	}

	ns, err := Create(logf, tunWrap, eng, magicSock, dialer, dns)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ns.ProcessLocalIPs = true
	if err := ns.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return true })

	pkt := &packet.Parsed{}
	const N = 10_000
	ms0 := getMemStats()
	for i := 0; i < N; i++ {
		outcome := ns.injectInbound(pkt, tunWrap)
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

func TestNetstackLeakMode(t *testing.T) {
	// See the comments in init(), and/or in issue #4309.
	// Influenced by an envknob that may be useful in tests, so just check that
	// it's not the oddly behaving zero value.
	if refs.GetLeakMode() == 0 {
		t.Fatalf("refs.leakMode is 0, want a non-zero value")
	}
}

func makeNetstack(t *testing.T, config func(*Impl)) *Impl {
	tunDev := tstun.NewFake()
	dialer := new(tsdial.Dialer)
	logf := func(format string, args ...any) {
		if !t.Failed() {
			t.Helper()
			t.Logf(format, args...)
		}
	}
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Tun:    tunDev,
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })
	ig, ok := eng.(wgengine.InternalsGetter)
	if !ok {
		t.Fatal("not an InternalsGetter")
	}
	tunWrap, magicSock, dns, ok := ig.GetInternals()
	if !ok {
		t.Fatal("failed to get internals")
	}

	ns, err := Create(logf, tunWrap, eng, magicSock, dialer, dns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })

	ns.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return true })
	config(ns)

	if err := ns.Start(); err != nil {
		t.Fatalf("Start: %v", err)
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
		name      string
		pkt       *packet.Parsed
		setup     func(*Impl)
		want      bool
		runOnGOOS string
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
			setup: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					// $ tailscale debug via 7 10.1.1.0/24
					// fd7a:115c:a1e0:b1a:0:7:a01:100/120
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:100/120"),
				}
				i.lb.Start(ipn.Options{
					LegacyMigrationPrefs: prefs,
				})
				i.atomicIsLocalIPFunc.Store(looksLikeATailscaleSelfAddress)

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
			setup: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					// tailscale debug via 7 10.1.2.0/24
					// fd7a:115c:a1e0:b1a:0:7:a01:200/120
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7:a01:200/120"),
				}
				i.lb.Start(ipn.Options{
					LegacyMigrationPrefs: prefs,
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
			setup: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.RunSSH = true
				i.lb.Start(ipn.Options{
					LegacyMigrationPrefs: prefs,
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
			setup: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.RunSSH = false // default, but to be explicit
				i.lb.Start(ipn.Options{
					LegacyMigrationPrefs: prefs,
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
			setup: func(i *Impl) {
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
			setup: func(i *Impl) {
				i.ProcessSubnets = true

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
			setup: func(i *Impl) {
				prefs := ipn.NewPrefs()
				prefs.AdvertiseRoutes = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.1/24"),
				}
				i.lb.Start(ipn.Options{
					LegacyMigrationPrefs: prefs,
				})

				// As if we were running on Linux where netstack isn't used.
				i.ProcessSubnets = false
				i.atomicIsLocalIPFunc.Store(func(netip.Addr) bool { return false })

				// Set the PeerAPI port to the Dst port above.
				atomic.StoreUint32(&i.peerapiPort4Atomic, 5555)
				atomic.StoreUint32(&i.peerapiPort6Atomic, 5555)
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
			impl := makeNetstack(t, func(i *Impl) {
				defer t.Logf("netstack setup finished")

				logf := tstest.WhileTestRunningLogger(t)
				e, err := wgengine.NewFakeUserspaceEngine(logf, 0)
				if err != nil {
					t.Fatalf("NewFakeUserspaceEngine: %v", err)
				}
				t.Cleanup(e.Close)

				lb, err := ipnlocal.NewLocalBackend(logf, "logid", new(mem.Store), "", new(tsdial.Dialer), e, 0)
				if err != nil {
					t.Fatalf("NewLocalBackend: %v", err)
				}
				t.Cleanup(lb.Shutdown)
				dir := t.TempDir()
				lb.SetVarRoot(dir)

				i.SetLocalBackend(lb)

				if tc.setup != nil {
					tc.setup(i)
				}
			})
			got := impl.shouldProcessInbound(tc.pkt, nil)
			if got != tc.want {
				t.Errorf("got shouldProcessInbound()=%v; want %v", got, tc.want)
			} else {
				t.Logf("OK: shouldProcessInbound() = %v", got)
			}
		})
	}
}
