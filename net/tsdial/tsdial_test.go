// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaissmai/bart"
)

func TestUserDialPlan(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		routes         map[netip.Prefix]bool // nil means no routes configured
		useNetstackFor func(netip.Addr) bool // nil means not set
		wantVia        bool
		wantAddr       netip.AddrPort
	}{
		{
			name:     "loopback_no_routes",
			addr:     "127.0.0.1:8080",
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("127.0.0.1:8080"),
		},
		{
			name:     "loopback_v6_no_routes",
			addr:     "[::1]:8080",
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("[::1]:8080"),
		},
		{
			name: "tailscale_ip_in_routes",
			addr: "100.64.1.1:22",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
			},
			wantVia:  true,
			wantAddr: netip.MustParseAddrPort("100.64.1.1:22"),
		},
		{
			name: "non_tailscale_ip_in_local_routes",
			addr: "10.0.0.5:80",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
				netip.MustParsePrefix("10.0.0.0/8"):    false, // local route
			},
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("10.0.0.5:80"),
		},
		{
			name: "loopback_with_routes_configured",
			addr: "127.0.0.1:3000",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
			},
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("127.0.0.1:3000"),
		},
		{
			name: "netstack_for_ip",
			addr: "100.100.100.100:53",
			useNetstackFor: func(ip netip.Addr) bool {
				return ip == netip.MustParseAddr("100.100.100.100")
			},
			wantVia:  true,
			wantAddr: netip.MustParseAddrPort("100.100.100.100:53"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Dialer{}
			if tt.routes != nil {
				rt := &bart.Table[bool]{}
				for pfx, v := range tt.routes {
					rt.Insert(pfx, v)
				}
				d.routes.Store(rt)
			}
			d.UseNetstackForIP = tt.useNetstackFor

			ipp, viaTailscale, err := d.UserDialPlan(context.Background(), "tcp", tt.addr)
			if err != nil {
				t.Fatalf("UserDialPlan: %v", err)
			}
			if viaTailscale != tt.wantVia {
				t.Errorf("viaTailscale = %v, want %v", viaTailscale, tt.wantVia)
			}
			if ipp != tt.wantAddr {
				t.Errorf("addr = %v, want %v", ipp, tt.wantAddr)
			}
		})
	}
}

// TestRaceDialUserFallback covers the core happy-eyeballs scenario:
// the first family (e.g. AAAA via an IPv4-only exit node) fails to
// connect, and the second family succeeds. The fallback delay should
// not be required because the failing dial wakes the launcher via
// failBoost.
func TestRaceDialUserFallback(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::1]:80")
	v4 := netip.MustParseAddrPort("192.0.2.1:80")

	var v4Calls, v6Calls atomic.Int32
	d := &Dialer{
		UseNetstackForIP: func(netip.Addr) bool { return true },
		NetstackDialTCP: func(ctx context.Context, ipp netip.AddrPort) (net.Conn, error) {
			if ipp.Addr().Is6() {
				v6Calls.Add(1)
				return nil, errors.New("simulated v6 unreachable")
			}
			v4Calls.Add(1)
			c, _ := net.Pipe()
			return c, nil
		},
		NetstackDialUDP: func(context.Context, netip.AddrPort) (net.Conn, error) {
			t.Fatal("UDP dialer should not be called for TCP race")
			return nil, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t0 := time.Now()
	c, err := d.raceDialUser(ctx, []netip.AddrPort{v6, v4})
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("raceDialUser: %v", err)
	}
	defer c.Close()

	if v6Calls.Load() != 1 {
		t.Errorf("v6 dial attempts = %d, want 1", v6Calls.Load())
	}
	if v4Calls.Load() != 1 {
		t.Errorf("v4 dial attempts = %d, want 1", v4Calls.Load())
	}
	// We allow up to the fallback delay; with failBoost the v4 attempt
	// should kick off as soon as v6 fails, well under the timer.
	if elapsed >= userDialFallbackDelay {
		t.Errorf("race took %v; expected failBoost to short-circuit the %v delay",
			elapsed, userDialFallbackDelay)
	}
}

// TestRaceDialUserAllFail verifies that when every candidate fails,
// raceDialUser returns the first error rather than hanging.
func TestRaceDialUserAllFail(t *testing.T) {
	ipps := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:80"),
		netip.MustParseAddrPort("192.0.2.1:80"),
	}
	d := &Dialer{
		UseNetstackForIP: func(netip.Addr) bool { return true },
		NetstackDialTCP: func(_ context.Context, ipp netip.AddrPort) (net.Conn, error) {
			return nil, errors.New("nope: " + ipp.String())
		},
		NetstackDialUDP: func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, nil },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.raceDialUser(ctx, ipps)
	if err == nil {
		t.Fatal("raceDialUser returned nil error; want error")
	}
}

// TestRaceDialUserCancelsLosers verifies that once one dial succeeds,
// any other in-flight dial is cancelled and any conn it eventually
// produces is closed (rather than leaked).
func TestRaceDialUserCancelsLosers(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::1]:80")
	v4 := netip.MustParseAddrPort("192.0.2.1:80")

	// v6 blocks until its context is cancelled, then returns a conn we
	// must verify is closed.
	closed := make(chan struct{})
	d := &Dialer{
		UseNetstackForIP: func(netip.Addr) bool { return true },
		NetstackDialTCP: func(ctx context.Context, ipp netip.AddrPort) (net.Conn, error) {
			if ipp.Addr().Is6() {
				<-ctx.Done()
				a, b := net.Pipe()
				go func() {
					<-closed
					b.Close()
				}()
				return &closingPipeConn{Conn: a, closed: closed}, nil
			}
			c, _ := net.Pipe()
			return c, nil
		},
		NetstackDialUDP: func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, nil },
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.raceDialUser(ctx, []netip.AddrPort{v6, v4})
	if err != nil {
		t.Fatalf("raceDialUser: %v", err)
	}
	defer c.Close()

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("loser conn was not closed within 2s")
	}
}

type closingPipeConn struct {
	net.Conn
	closed chan struct{}
}

func (c *closingPipeConn) Close() error {
	select {
	case <-c.closed:
		// already closed
	default:
		close(c.closed)
	}
	return c.Conn.Close()
}
