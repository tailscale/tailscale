// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"net"
	"testing"
)

func TestGetList(t *testing.T) {
	pl, err := GetList(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pl {
		t.Logf("[%d] %+v", i, p)
	}
	t.Logf("As String: %v", pl.String())
}

func TestIgnoreLocallyBoundPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("failed to bind: %v", err)
	}
	defer ln.Close()
	ta := ln.Addr().(*net.TCPAddr)
	port := ta.Port
	pl, err := GetList(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl {
		if p.Proto == "tcp" && int(p.Port) == port {
			t.Fatal("didn't expect to find test's localhost ephemeral port")
		}
	}
}

func BenchmarkGetList(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := GetList(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
