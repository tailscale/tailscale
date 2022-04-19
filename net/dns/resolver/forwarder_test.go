// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"flag"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/hostinfo"
	"tailscale.com/types/dnstype"
)

func (rr resolverAndDelay) String() string {
	return fmt.Sprintf("%v+%v", rr.name, rr.startDelay)
}

func TestResolversWithDelays(t *testing.T) {
	// query
	q := func(ss ...string) (ipps []dnstype.Resolver) {
		for _, host := range ss {
			ipps = append(ipps, dnstype.Resolver{Addr: host})
		}
		return
	}
	// output
	o := func(ss ...string) (rr []resolverAndDelay) {
		for _, s := range ss {
			var d time.Duration
			s, durStr, hasPlus := strings.Cut(s, "+")
			if hasPlus {
				var err error
				d, err = time.ParseDuration(durStr)
				if err != nil {
					panic(fmt.Sprintf("parsing duration in %q: %v", s, err))
				}
			}
			rr = append(rr, resolverAndDelay{
				name:       dnstype.Resolver{Addr: s},
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
			in:   q("1.2.3.4", "2.3.4.5"),
			want: o("1.2.3.4", "2.3.4.5"),
		},
		{
			name: "google-all-ipv4",
			in:   q("8.8.8.8", "8.8.4.4"),
			want: o("https://dns.google/dns-query", "8.8.8.8+0.5s", "8.8.4.4+0.7s"),
		},
		{
			name: "google-only-ipv6",
			in:   q("2001:4860:4860::8888", "2001:4860:4860::8844"),
			want: o("https://dns.google/dns-query", "2001:4860:4860::8888+0.5s", "2001:4860:4860::8844+0.7s"),
		},
		{
			name: "google-all-four",
			in:   q("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
			want: o("https://dns.google/dns-query", "8.8.8.8+0.5s", "8.8.4.4+0.7s", "2001:4860:4860::8888+0.5s", "2001:4860:4860::8844+0.7s"),
		},
		{
			name: "quad9-one-v4-one-v6",
			in:   q("9.9.9.9", "2620:fe::fe"),
			want: o("https://dns.quad9.net/dns-query", "9.9.9.9+0.5s", "2620:fe::fe+0.5s"),
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

func TestGetRCode(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   dns.RCode
	}{
		{
			name:   "empty",
			packet: []byte{},
			want:   dns.RCode(5),
		},
		{
			name:   "too-short",
			packet: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			want:   dns.RCode(5),
		},
		{
			name:   "noerror",
			packet: []byte{0xC4, 0xFE, 0x81, 0xA0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			want:   dns.RCode(0),
		},
		{
			name:   "refused",
			packet: []byte{0xee, 0xa1, 0x81, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want:   dns.RCode(5),
		},
		{
			name:   "nxdomain",
			packet: []byte{0x34, 0xf4, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
			want:   dns.RCode(3),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRCode(tt.packet)
			if got != tt.want {
				t.Errorf("got %d; want %d", got, tt.want)
			}
		})
	}
}

func TestMaxDoHInFlight(t *testing.T) {
	tests := []struct {
		goos string
		ver  string
		want int
	}{
		{"ios", "", 10},
		{"ios", "1532", 10},
		{"ios", "9.3.2", 10},
		{"ios", "14.3.2", 10},
		{"ios", "15.3.2", 1000},
		{"ios", "20.3.2", 1000},
		{"android", "", 1000},
		{"darwin", "", 1000},
		{"linux", "", 1000},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s-%s", tc.goos, tc.ver), func(t *testing.T) {
			hostinfo.SetOSVersion(tc.ver)
			got := maxDoHInFlight(tc.goos)
			if got != tc.want {
				t.Errorf("got %d; want %d", got, tc.want)
			}
		})
	}
}

var testDNS = flag.Bool("test-dns", false, "run tests that require a working DNS server")

func TestGetKnownDoHClientForProvider(t *testing.T) {
	var fwd forwarder
	c, ok := fwd.getKnownDoHClientForProvider("https://dns.google/dns-query")
	if !ok {
		t.Fatal("not found")
	}
	if !*testDNS {
		t.Skip("skipping without --test-dns")
	}
	res, err := c.Head("https://dns.google/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	t.Logf("Got: %+v", res)
}

func BenchmarkNameFromQuery(b *testing.B) {
	builder := dns.NewBuilder(nil, dns.Header{})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  dns.MustNewName("foo.example."),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	})
	msg, err := builder.Finish()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := nameFromQuery(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
