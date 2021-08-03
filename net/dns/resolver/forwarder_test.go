// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/types/dnstype"
)

func (rr resolverAndDelay) String() string {
	return fmt.Sprintf("%v+%v", rr.name, rr.startDelay)
}

func TestResolversWithDelays(t *testing.T) {
	// query
	q := func(ss ...string) (ipps []dnstype.Resolver) {
		for _, s := range ss {
			host, _, err := net.SplitHostPort(s)
			if err != nil {
				t.Fatal(err)
			}
			ipps = append(ipps, dnstype.Resolver{Addr: host})
		}
		return
	}
	// output
	o := func(ss ...string) (rr []resolverAndDelay) {
		for _, s := range ss {
			var d time.Duration
			if i := strings.Index(s, "+"); i != -1 {
				var err error
				d, err = time.ParseDuration(s[i+1:])
				if err != nil {
					panic(fmt.Sprintf("parsing duration in %q: %v", s, err))
				}
				s = s[:i]
			}
			host, _, err := net.SplitHostPort(s)
			if err != nil {
				t.Fatal(err)
			}
			rr = append(rr, resolverAndDelay{
				name:       dnstype.Resolver{Addr: host},
				startDelay: d,
			})
		}
		return
	}

	tests := []struct {
		name string
		in   []dnstype.Resolver
		want []resolverAndDelay
	}{
		{
			name: "unknown-no-delays",
			in:   q("1.2.3.4:53", "2.3.4.5:53"),
			want: o("1.2.3.4:53", "2.3.4.5:53"),
		},
		{
			name: "google-all-ipv4",
			in:   q("8.8.8.8:53", "8.8.4.4:53"),
			want: o("8.8.8.8:53", "8.8.4.4:53+200ms"),
		},
		{
			name: "google-only-ipv6",
			in:   q("[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53"),
			want: o("[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53+200ms"),
		},
		{
			name: "google-all-four",
			in:   q("8.8.8.8:53", "8.8.4.4:53", "[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53"),
			want: o("8.8.8.8:53", "8.8.4.4:53+200ms", "[2001:4860:4860::8888]:53+2.5s", "[2001:4860:4860::8844]:53+2.7s"),
		},
		{
			name: "quad9-one-v4-one-v6",
			in:   q("9.9.9.9:53", "[2620:fe::fe]:53"),
			want: o("9.9.9.9:53", "[2620:fe::fe]:53+200ms"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolversWithDelays(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}

}
