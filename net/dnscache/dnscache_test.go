// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"tailscale.com/tstest"
)

var dialTest = flag.String("dial-test", "", "if non-empty, addr:port to test dial")

func TestDialer(t *testing.T) {
	if *dialTest == "" {
		t.Skip("skipping; --dial-test is blank")
	}
	r := &Resolver{Logf: t.Logf}
	var std net.Dialer
	dialer := Dialer(std.DialContext, r)
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialer(ctx, "tcp", *dialTest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dialed in %v", time.Since(t0))
	c.Close()
}

func TestDialCall_DNSWasTrustworthy(t *testing.T) {
	type step struct {
		ip  netip.Addr // IP we pretended to dial
		err error      // the dial error or nil for success
	}
	mustIP := netip.MustParseAddr
	errFail := errors.New("some connect failure")
	tests := []struct {
		name  string
		steps []step
		want  bool
	}{
		{
			name: "no-info",
			want: false,
		},
		{
			name: "previous-dial",
			steps: []step{
				{mustIP("2003::1"), nil},
				{mustIP("2003::1"), errFail},
			},
			want: true,
		},
		{
			name: "no-previous-dial",
			steps: []step{
				{mustIP("2003::1"), errFail},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dialer{
				pastConnect: map[netip.Addr]time.Time{},
			}
			dc := &dialCall{
				d: d,
			}
			for _, st := range tt.steps {
				dc.noteDialResult(st.ip, st.err)
			}
			got := dc.dnsWasTrustworthy()
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDialCall_uniqueIPs(t *testing.T) {
	dc := &dialCall{}
	mustIP := netip.MustParseAddr
	errFail := errors.New("some connect failure")
	dc.noteDialResult(mustIP("2003::1"), errFail)
	dc.noteDialResult(mustIP("2003::2"), errFail)
	got := dc.uniqueIPs([]netip.Addr{
		mustIP("2003::1"),
		mustIP("2003::2"),
		mustIP("2003::2"),
		mustIP("2003::3"),
		mustIP("2003::3"),
		mustIP("2003::4"),
		mustIP("2003::4"),
	})
	want := []netip.Addr{
		mustIP("2003::3"),
		mustIP("2003::4"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestResolverAllHostStaticResult(t *testing.T) {
	r := &Resolver{
		Logf:       t.Logf,
		SingleHost: "foo.bar",
		SingleHostStaticResult: []netip.Addr{
			netip.MustParseAddr("2001:4860:4860::8888"),
			netip.MustParseAddr("2001:4860:4860::8844"),
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		},
	}
	ip4, ip6, allIPs, err := r.LookupIP(context.Background(), "foo.bar")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ip4.String(), "8.8.8.8"; got != want {
		t.Errorf("ip4 got %q; want %q", got, want)
	}
	if got, want := ip6.String(), "2001:4860:4860::8888"; got != want {
		t.Errorf("ip4 got %q; want %q", got, want)
	}
	if got, want := fmt.Sprintf("%q", allIPs), `["2001:4860:4860::8888" "2001:4860:4860::8844" "8.8.8.8" "8.8.4.4"]`; got != want {
		t.Errorf("allIPs got %q; want %q", got, want)
	}

	_, _, _, err = r.LookupIP(context.Background(), "bad")
	if got, want := fmt.Sprint(err), `dnscache: unexpected hostname "bad" doesn't match expected "foo.bar"`; got != want {
		t.Errorf("bad dial error got %q; want %q", got, want)
	}
}

func TestShouldTryBootstrap(t *testing.T) {
	tstest.Replace(t, &debug, func() bool { return true })

	type step struct {
		ip  netip.Addr // IP we pretended to dial
		err error      // the dial error or nil for success
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	deadlineExceeded, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	ctx := context.Background()
	errFailed := errors.New("some failure")

	cacheWithFallback := &Resolver{
		Logf: t.Logf,
		LookupIPFallback: func(_ context.Context, _ string) ([]netip.Addr, error) {
			panic("unimplemented")
		},
	}
	cacheNoFallback := &Resolver{Logf: t.Logf}

	testCases := []struct {
		name       string
		steps      []step
		ctx        context.Context
		err        error
		noFallback bool
		want       bool
	}{
		{
			name: "no-error",
			ctx:  ctx,
			err:  nil,
			want: false,
		},
		{
			name: "canceled",
			ctx:  canceled,
			err:  errFailed,
			want: false,
		},
		{
			name: "deadline-exceeded",
			ctx:  deadlineExceeded,
			err:  errFailed,
			want: false,
		},
		{
			name:       "no-fallback",
			ctx:        ctx,
			err:        errFailed,
			noFallback: true,
			want:       false,
		},
		{
			name: "dns-was-trustworthy",
			ctx:  ctx,
			err:  errFailed,
			steps: []step{
				{netip.MustParseAddr("2003::1"), nil},
				{netip.MustParseAddr("2003::1"), errFailed},
			},
			want: false,
		},
		{
			name: "should-bootstrap",
			ctx:  ctx,
			err:  errFailed,
			want: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := &dialer{
				pastConnect: map[netip.Addr]time.Time{},
			}
			if tt.noFallback {
				d.dnsCache = cacheNoFallback
			} else {
				d.dnsCache = cacheWithFallback
			}
			dc := &dialCall{d: d}
			for _, st := range tt.steps {
				dc.noteDialResult(st.ip, st.err)
			}
			got := d.shouldTryBootstrap(tt.ctx, tt.err, dc)
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestSingleHostStaticResult(t *testing.T) {
	v4 := netip.MustParseAddr("0.0.0.1")
	v6 := netip.MustParseAddr("2001::a")

	tests := []struct {
		name    string
		static  []netip.Addr
		wantIP  netip.Addr
		wantIP6 netip.Addr
		wantAll []netip.Addr
	}{
		{
			name:    "just-v6",
			static:  []netip.Addr{v6},
			wantIP:  v6,
			wantIP6: v6,
			wantAll: []netip.Addr{v6},
		},
		{
			name:    "just-v4",
			static:  []netip.Addr{v4},
			wantIP:  v4,
			wantIP6: netip.Addr{},
			wantAll: []netip.Addr{v4},
		},
		{
			name:    "v6-then-v4",
			static:  []netip.Addr{v6, v4},
			wantIP:  v4,
			wantIP6: v6,
			wantAll: []netip.Addr{v6, v4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{
				SingleHost:             "example.com",
				SingleHostStaticResult: tt.static,
			}
			ip, ip6, all, err := r.LookupIP(context.Background(), "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if ip != tt.wantIP {
				t.Errorf("got ip %v; want %v", ip, tt.wantIP)
			}
			if ip6 != tt.wantIP6 {
				t.Errorf("got ip6 %v; want %v", ip6, tt.wantIP6)
			}
			if !slices.Equal(all, tt.wantAll) {
				t.Errorf("got all %v; want %v", all, tt.wantAll)
			}
		})
	}
}

type persistCall struct {
	host, resolver string
	ips            []netip.Addr
}

func TestDiskCacheHooks(t *testing.T) {
	mustIPs := func(ss ...string) (ips []netip.Addr) {
		for _, s := range ss {
			ips = append(ips, netip.MustParseAddr(s))
		}
		return ips
	}
	errFailed := errors.New("some resolution failure")

	t.Run("persist-on-success", func(t *testing.T) {
		var calls []persistCall
		defer HookPersistResolution.SetForTest(func(host, resolver string, ips []netip.Addr) {
			calls = append(calls, persistCall{host, resolver, ips})
		})()
		r := &Resolver{
			Logf: t.Logf,
			LookupIPForTest: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return mustIPs("1.1.1.1", "2600::1"), nil
			},
		}
		if _, _, _, err := r.LookupIP(t.Context(), "ctrl.example.com"); err != nil {
			t.Fatal(err)
		}
		want := []persistCall{{"ctrl.example.com", "forward", mustIPs("1.1.1.1", "2600::1")}}
		if !reflect.DeepEqual(calls, want) {
			t.Errorf("persist calls = %+v; want %+v", calls, want)
		}
	})

	t.Run("disk-hit-before-derp", func(t *testing.T) {
		defer HookLookupDiskCache.SetForTest(func(host string) ([]netip.Addr, bool) {
			if host != "ctrl.example.com" {
				t.Errorf("disk lookup host = %q; want ctrl.example.com", host)
			}
			return mustIPs("2.2.2.2"), true
		})()
		var persisted []persistCall
		defer HookPersistResolution.SetForTest(func(host, resolver string, ips []netip.Addr) {
			persisted = append(persisted, persistCall{host, resolver, ips})
		})()
		r := &Resolver{
			Logf: t.Logf,
			LookupIPForTest: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return nil, errFailed
			},
			LookupIPFallback: func(ctx context.Context, host string) ([]netip.Addr, error) {
				t.Error("DERP fallback used despite disk cache hit")
				return nil, errFailed
			},
		}
		hits0 := metricDiskFallbackHit.Value()
		ip, _, _, err := r.LookupIP(t.Context(), "ctrl.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if want := netip.MustParseAddr("2.2.2.2"); ip != want {
			t.Errorf("ip = %v; want %v", ip, want)
		}
		if d := metricDiskFallbackHit.Value() - hits0; d != 1 {
			t.Errorf("disk fallback hit metric delta = %d; want 1", d)
		}
		if len(persisted) != 0 {
			t.Errorf("disk-sourced result was re-persisted: %+v", persisted)
		}
	})

	t.Run("disk-miss-uses-derp", func(t *testing.T) {
		defer HookLookupDiskCache.SetForTest(func(host string) ([]netip.Addr, bool) {
			return nil, false
		})()
		var persisted []persistCall
		defer HookPersistResolution.SetForTest(func(host, resolver string, ips []netip.Addr) {
			persisted = append(persisted, persistCall{host, resolver, ips})
		})()
		r := &Resolver{
			Logf: t.Logf,
			LookupIPForTest: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return nil, errFailed
			},
			LookupIPFallback: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return mustIPs("3.3.3.3"), nil
			},
		}
		miss0 := metricDiskFallbackMiss.Value()
		derp0 := metricDERPFallbackOK.Value()
		ip, _, _, err := r.LookupIP(t.Context(), "ctrl.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if want := netip.MustParseAddr("3.3.3.3"); ip != want {
			t.Errorf("ip = %v; want %v", ip, want)
		}
		if d := metricDiskFallbackMiss.Value() - miss0; d != 1 {
			t.Errorf("disk fallback miss metric delta = %d; want 1", d)
		}
		if d := metricDERPFallbackOK.Value() - derp0; d != 1 {
			t.Errorf("DERP fallback ok metric delta = %d; want 1", d)
		}
		want := []persistCall{{"ctrl.example.com", "fallback", mustIPs("3.3.3.3")}}
		if !reflect.DeepEqual(persisted, want) {
			t.Errorf("persist calls = %+v; want %+v", persisted, want)
		}
	})
}
