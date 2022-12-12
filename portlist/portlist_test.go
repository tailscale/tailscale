// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portlist

import (
	"context"
	"flag"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestGetList(t *testing.T) {
	tstest.ResourceCheck(t)

	var p Poller
	pl, err := p.getList()
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pl {
		t.Logf("[%d] %+v", i, p)
	}
	t.Logf("As String: %v", pl.String())
}

func TestIgnoreLocallyBoundPorts(t *testing.T) {
	tstest.ResourceCheck(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("failed to bind: %v", err)
	}
	defer ln.Close()
	ta := ln.Addr().(*net.TCPAddr)
	port := ta.Port
	var p Poller
	pl, err := p.getList()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl {
		if p.Proto == "tcp" && int(p.Port) == port {
			t.Fatal("didn't expect to find test's localhost ephemeral port")
		}
	}
}

var flagRunUnspecTests = flag.Bool("run-unspec-tests",
	runtime.GOOS == "linux", // other OSes have annoying firewall GUI confirmation dialogs
	"run tests that require listening on the the unspecified address")

func TestChangesOverTime(t *testing.T) {
	if !*flagRunUnspecTests {
		t.Skip("skipping test without --run-unspec-tests")
	}

	var p Poller
	get := func(t *testing.T) []Port {
		t.Helper()
		s, err := p.getList()
		if err != nil {
			t.Fatal(err)
		}
		return append([]Port(nil), s...)
	}

	p1 := get(t)
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skipf("failed to bind: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	containsPort := func(pl List) bool {
		for _, p := range pl {
			if p.Proto == "tcp" && p.Port == port {
				return true
			}
		}
		return false
	}
	if containsPort(p1) {
		t.Error("unexpectedly found ephemeral port in p1, before it was opened", port)
	}
	p2 := get(t)
	if !containsPort(p2) {
		t.Error("didn't find ephemeral port in p2", port)
	}
	ln.Close()
	p3 := get(t)
	if containsPort(p3) {
		t.Error("unexpectedly found ephemeral port in p3, after it was closed", port)
	}
}

func TestEqualLessThan(t *testing.T) {
	tests := []struct {
		name string
		a, b Port
		want bool
	}{
		{
			"Port a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			Port{Proto: "tcp", Port: 101, Process: "proc1"},
			true,
		},
		{
			"Port a > b",
			Port{Proto: "tcp", Port: 101, Process: "proc1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			false,
		},
		{
			"Proto a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			Port{Proto: "udp", Port: 100, Process: "proc1"},
			true,
		},
		{
			"Proto a < b",
			Port{Proto: "udp", Port: 100, Process: "proc1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			false,
		},
		{
			"Process a < b",
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			Port{Proto: "tcp", Port: 100, Process: "proc2"},
			true,
		},
		{
			"Process a > b",
			Port{Proto: "tcp", Port: 100, Process: "proc2"},
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			false,
		},
		{
			"Port evaluated first",
			Port{Proto: "udp", Port: 100, Process: "proc2"},
			Port{Proto: "tcp", Port: 101, Process: "proc1"},
			true,
		},
		{
			"Proto evaluated second",
			Port{Proto: "tcp", Port: 100, Process: "proc2"},
			Port{Proto: "udp", Port: 100, Process: "proc1"},
			true,
		},
		{
			"Process evaluated fourth",
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			Port{Proto: "tcp", Port: 100, Process: "proc2"},
			true,
		},
		{
			"equal",
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			Port{Proto: "tcp", Port: 100, Process: "proc1"},
			false,
		},
	}

	for _, tt := range tests {
		got := tt.a.lessThan(&tt.b)
		if got != tt.want {
			t.Errorf("%s: Equal = %v; want %v", tt.name, got, tt.want)
		}
		lessBack := tt.b.lessThan(&tt.a)
		if got && lessBack {
			t.Errorf("%s: both a and b report being less than each other", tt.name)
		}
		wantEqual := !got && !lessBack
		gotEqual := tt.a.equal(&tt.b)
		if gotEqual != wantEqual {
			t.Errorf("%s: equal = %v; want %v", tt.name, gotEqual, wantEqual)
		}
	}
}

func TestPoller(t *testing.T) {
	p, err := NewPoller()
	if err != nil {
		t.Skipf("not running test: %v", err)
	}
	defer p.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	gotUpdate := make(chan bool, 16)

	go func() {
		defer wg.Done()
		for pl := range p.Updates() {
			// Look at all the pl slice memory to maximize
			// chance of race detector seeing violations.
			for _, v := range pl {
				if v == (Port{}) {
					// Force use
					panic("empty port")
				}
			}
			select {
			case gotUpdate <- true:
			default:
			}
		}
	}()

	tick := make(chan time.Time, 16)
	go func() {
		defer wg.Done()
		if err := p.runWithTickChan(context.Background(), tick); err != nil {
			t.Error("runWithTickChan:", err)
		}
	}()
	for i := 0; i < 10; i++ {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		tick <- time.Time{}

		select {
		case <-gotUpdate:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for update")
		}
	}

	// And a bunch of ticks without waiting for updates,
	// to make race tests more likely to fail, if any present.
	for i := 0; i < 10; i++ {
		tick <- time.Time{}
	}

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func BenchmarkGetList(b *testing.B) {
	benchmarkGetList(b, false)
}

func BenchmarkGetListIncremental(b *testing.B) {
	benchmarkGetList(b, true)
}

func benchmarkGetList(b *testing.B, incremental bool) {
	b.ReportAllocs()
	var p Poller
	for i := 0; i < b.N; i++ {
		pl, err := p.getList()
		if err != nil {
			b.Fatal(err)
		}
		if incremental {
			p.prev = pl
		}
	}
}
