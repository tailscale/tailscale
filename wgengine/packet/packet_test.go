// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"net"
	"testing"
)

func TestIPString(t *testing.T) {
	const str = "1.2.3.4"
	ip := NewIP(net.ParseIP(str))

	var got string
	allocs := testing.AllocsPerRun(1000, func() {
		got = ip.String()
	})

	if got != str {
		t.Errorf("got %q; want %q", got, str)
	}
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}

func TestQDecodeString(t *testing.T) {
	q := QDecode{
		IPProto: TCP,
		SrcIP:   NewIP(net.ParseIP("1.2.3.4")),
		SrcPort: 123,
		DstIP:   NewIP(net.ParseIP("5.6.7.8")),
		DstPort: 567,
	}
	got := q.String()
	want := "TCP{1.2.3.4:123 > 5.6.7.8:567}"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		got = q.String()
	})
	if allocs != 1 {
		t.Errorf("allocs = %v; want 1", allocs)
	}
}
