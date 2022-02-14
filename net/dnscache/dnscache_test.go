// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnscache

import (
	"context"
	"errors"
	"flag"
	"net"
	"reflect"
	"testing"
	"time"

	"inet.af/netaddr"
)

var dialTest = flag.String("dial-test", "", "if non-empty, addr:port to test dial")

func TestDialer(t *testing.T) {
	if *dialTest == "" {
		t.Skip("skipping; --dial-test is blank")
	}
	r := new(Resolver)
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
		ip  netaddr.IP // IP we pretended to dial
		err error      // the dial error or nil for success
	}
	mustIP := netaddr.MustParseIP
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
				pastConnect: map[netaddr.IP]time.Time{},
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
	mustIP := netaddr.MustParseIP
	errFail := errors.New("some connect failure")
	dc.noteDialResult(mustIP("2003::1"), errFail)
	dc.noteDialResult(mustIP("2003::2"), errFail)
	got := dc.uniqueIPs([]netaddr.IP{
		mustIP("2003::1"),
		mustIP("2003::2"),
		mustIP("2003::2"),
		mustIP("2003::3"),
		mustIP("2003::3"),
		mustIP("2003::4"),
		mustIP("2003::4"),
	})
	want := []netaddr.IP{
		mustIP("2003::3"),
		mustIP("2003::4"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}
