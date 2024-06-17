// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipset

import (
	"net/netip"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/types/views"
)

func pp(ss ...string) (ret []netip.Prefix) {
	for _, s := range ss {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return
}

func aa(ss ...string) (ret []netip.Addr) {
	for _, s := range ss {
		ret = append(ret, netip.MustParseAddr(s))
	}
	return
}

var newContainsIPFuncTests = []struct {
	name    string
	pfx     []netip.Prefix
	want    string
	wantIn  []netip.Addr
	wantOut []netip.Addr
}{
	{
		name:    "empty",
		pfx:     pp(),
		want:    "empty",
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "cidr-list-1",
		pfx:     pp("10.0.0.0/8"),
		want:    "one-prefix",
		wantIn:  aa("10.0.0.1", "10.2.3.4"),
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "cidr-list-2",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "3.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-3",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "5.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-4",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "7.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-5",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8", "9.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "9.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name: "cidr-list-10",
		pfx: pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8", "9.0.0.0/8",
			"11.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "17.0.0.0/8", "19.0.0.0/8"),
		want:    "bart", // big enough that bart is faster than linear-contains
		wantIn:  aa("1.0.0.1", "19.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "one-ip",
		pfx:     pp("10.1.0.0/32"),
		want:    "one-ip",
		wantIn:  aa("10.1.0.0"),
		wantOut: aa("10.0.0.9"),
	},
	{
		name:    "two-ip",
		pfx:     pp("10.1.0.0/32", "10.2.0.0/32"),
		want:    "two-ip",
		wantIn:  aa("10.1.0.0", "10.2.0.0"),
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "three-ip",
		pfx:     pp("10.1.0.0/32", "10.2.0.0/32", "10.3.0.0/32"),
		want:    "ip-map",
		wantIn:  aa("10.1.0.0", "10.2.0.0"),
		wantOut: aa("8.8.8.8"),
	},
}

func BenchmarkNewContainsIPFunc(b *testing.B) {
	for _, tt := range newContainsIPFuncTests {
		b.Run(tt.name, func(b *testing.B) {
			f := NewContainsIPFunc(views.SliceOf(tt.pfx))
			for i := 0; i < b.N; i++ {
				for _, ip := range tt.wantIn {
					if !f(ip) {
						b.Fatal("unexpected false")
					}
				}
				for _, ip := range tt.wantOut {
					if f(ip) {
						b.Fatal("unexpected true")
					}
				}
			}
		})
	}
}

func TestNewContainsIPFunc(t *testing.T) {
	for _, tt := range newContainsIPFuncTests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			tstest.Replace(t, &pathForTest, func(path string) { got = path })

			f := NewContainsIPFunc(views.SliceOf(tt.pfx))
			if got != tt.want {
				t.Errorf("func type = %q; want %q", got, tt.want)
			}
			for _, ip := range tt.wantIn {
				if !f(ip) {
					t.Errorf("match(%v) = false; want true", ip)
				}
			}
			for _, ip := range tt.wantOut {
				if f(ip) {
					t.Errorf("match(%v) = true; want false", ip)
				}
			}
		})
	}
}
