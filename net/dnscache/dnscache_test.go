// Copyright (c) Tailscale Inc & AUTHORS
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

func TestLocalhost(t *testing.T) {
	tstest.Replace(t, &debug, func() bool { return true })

	r := &Resolver{
		Logf: t.Logf,
		Forward: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// always return an error to force fallback
				return nil, errors.New("some error")
			},
		},
		LookupIPFallback: func(ctx context.Context, host string) ([]netip.Addr, error) {
			t.Errorf("unexpected call to LookupIPFallback(%q)", host)
			return nil, errors.New("unimplemented")
		},
	}

	// Just overriding the 'Dial' function in the *net.Resolver isn't
	// enough, because the Go resolver will read /etc/hosts and return
	// localhost from that.
	//
	// Abuse the IP cache to insert a fake localhost entry pointing to some
	// invalid IP; if we get this back, we know that we didn't hit our
	// hard-coded "localhost" logic.
	invalid4 := netip.MustParseAddr("169.254.169.254")
	invalid6 := netip.MustParseAddr("fe80::1")
	r.addIPCache("localhost", invalid4, invalid6, []netip.Addr{invalid4, invalid6}, 24*time.Hour)

	ip4, ip6, allIPs, err := r.LookupIP(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}

	localhost4 := netip.MustParseAddr("127.0.0.1")
	localhost6 := netip.MustParseAddr("::1")

	if ip4 != localhost4 {
		t.Errorf("ip4 got %q; want %q", ip4, localhost4)
	}
	if ip6 != localhost6 {
		t.Errorf("ip6 got %q; want %q", ip6, localhost6)
	}
	if !slices.Equal(allIPs, []netip.Addr{localhost4, localhost6}) {
		t.Errorf("allIPs got %q; want %q", allIPs, []netip.Addr{localhost4, localhost6})
	}
}
