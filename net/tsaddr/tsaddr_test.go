// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsaddr

import (
	"testing"

	"inet.af/netaddr"
)

func TestInCrostiniRange(t *testing.T) {
	tests := []struct {
		ip   netaddr.IP
		want bool
	}{
		{netaddr.IPv4(192, 168, 0, 1), false},
		{netaddr.IPv4(100, 101, 102, 103), false},
		{netaddr.IPv4(100, 115, 92, 0), true},
		{netaddr.IPv4(100, 115, 92, 5), true},
		{netaddr.IPv4(100, 115, 92, 255), true},
		{netaddr.IPv4(100, 115, 93, 40), true},
		{netaddr.IPv4(100, 115, 94, 1), false},
	}

	for _, test := range tests {
		if got := ChromeOSVMRange().Contains(test.ip); got != test.want {
			t.Errorf("inCrostiniRange(%q) = %v, want %v", test.ip, got, test.want)
		}
	}
}

func TestChromeOSVMRange(t *testing.T) {
	if got, want := ChromeOSVMRange().String(), "100.115.92.0/23"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCGNATRange(t *testing.T) {
	if got, want := CGNATRange().String(), "100.64.0.0/10"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestIsUla(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"first ULA", "fc00::1", true},
		{"not ULA", "fb00::1", false},
		{"Tailscale", "fd7a:115c:a1e0::1", true},
		{"Cloud Run", "fddf:3978:feb1:d745::1", true},
		{"zeros", "0000:0000:0000:0000:0000:0000:0000:0000", false},
		{"Link Local", "fe80::1", false},
		{"Global", "2602::1", false},
	}

	for _, test := range tests {
		if got := IsULA(netaddr.MustParseIP(test.ip)); got != test.want {
			t.Errorf("IsULA(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}
