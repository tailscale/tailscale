// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

var (
	v4Addr1 = netip.MustParseAddrPort("192.0.2.1:443")
	v4Addr2 = netip.MustParseAddrPort("192.0.2.2:443")
	v6Addr1 = netip.MustParseAddrPort("[2001:db8::1]:443")
	v6Addr2 = netip.MustParseAddrPort("[2001:db8::2]:443")
)

func TestRaceDialFirstWins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		addrs := []netip.AddrPort{v6Addr1, v4Addr1, v6Addr2}
		t0 := time.Now()
		conn, err := RaceDial(context.Background(), addrs,
			func(ctx context.Context, network, address string) (net.Conn, error) {
				return fakeConn{}, nil
			},
			300*time.Millisecond,
		)
		if err != nil {
			t.Fatal(err)
		}
		if conn == nil {
			t.Fatal("expected non-nil conn")
		}
		conn.Close()
		if d := time.Since(t0); d != 0 {
			t.Fatalf("took %v; first dial wins immediately so no time should pass", d)
		}
	})
}

func TestRaceDialAllFail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		addrs := []netip.AddrPort{v4Addr1, v6Addr1}
		want := errors.New("dial failed")
		t0 := time.Now()
		_, err := RaceDial(context.Background(), addrs,
			func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, want
			},
			300*time.Millisecond,
		)
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, want) {
			t.Fatalf("got %v; want %v", err, want)
		}
		if d := time.Since(t0); d != 0 {
			t.Fatalf("took %v; failBoost should skip all delays", d)
		}
	})
}

func TestRaceDialCancelledContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		t0 := time.Now()
		_, err := RaceDial(ctx, []netip.AddrPort{v4Addr1},
			func(ctx context.Context, network, address string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			300*time.Millisecond,
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v; want context.Canceled", err)
		}
		if d := time.Since(t0); d != 0 {
			t.Fatalf("took %v; pre-cancelled context should resolve immediately", d)
		}
	})
}

func TestRaceDialInterleaving(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var order []string
		addrs := []netip.AddrPort{v4Addr1, v4Addr2, v6Addr1, v6Addr2}
		t0 := time.Now()
		RaceDial(context.Background(), addrs,
			func(ctx context.Context, network, address string) (net.Conn, error) {
				order = append(order, address)
				return nil, errors.New("fail")
			},
			300*time.Millisecond,
		)
		if len(order) != 4 {
			t.Fatalf("expected 4 dials, got %d", len(order))
		}
		ipp, _ := netip.ParseAddrPort(order[0])
		if !ipp.Addr().Is6() {
			t.Errorf("first dial should be v6, got %v", order[0])
		}
		if d := time.Since(t0); d != 0 {
			t.Fatalf("took %v; failBoost should skip all delays", d)
		}
	})
}

func TestRaceDialFailBoost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		addrs := []netip.AddrPort{v6Addr1, v4Addr1, v6Addr2}
		t0 := time.Now()
		RaceDial(context.Background(), addrs,
			func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("fail")
			},
			time.Hour, // absurdly long; failBoost bypasses it
		)
		if d := time.Since(t0); d >= time.Second {
			t.Fatalf("took %v; failBoost should have bypassed the hour-long delay", d)
		}
	})
}
