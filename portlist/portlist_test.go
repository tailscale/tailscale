// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portlist

import (
	"net"
	"runtime"
	"testing"

	"tailscale.com/tstest"
)

func maybeSkip(t *testing.T) {
	if runtime.GOOS == "linux" {
		tstest.SkipOnKernelVersions(t,
			"https://github.com/tailscale/tailscale/issues/16966",
			"6.6.102", "6.6.103", "6.6.104",
			"6.12.42", "6.12.43", "6.12.44", "6.12.45",
		)
	}
}

func TestGetList(t *testing.T) {
	maybeSkip(t)
	tstest.ResourceCheck(t)

	var p Poller
	pl, _, err := p.Poll()
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range pl {
		t.Logf("[%d] %+v", i, p)
	}
	t.Logf("As String: %s", List(pl))
}

func TestIgnoreLocallyBoundPorts(t *testing.T) {
	maybeSkip(t)
	tstest.ResourceCheck(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("failed to bind: %v", err)
	}
	defer ln.Close()
	ta := ln.Addr().(*net.TCPAddr)
	port := ta.Port
	var p Poller
	pl, _, err := p.Poll()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pl {
		if p.Proto == "tcp" && int(p.Port) == port {
			t.Fatal("didn't expect to find test's localhost ephemeral port")
		}
	}
}

func TestPoller(t *testing.T) {
	maybeSkip(t)

	var p Poller
	p.IncludeLocalhost = true
	get := func(t *testing.T) []Port {
		t.Helper()
		s, _, err := p.Poll()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	p1 := get(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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

func TestClose(t *testing.T) {
	var p Poller
	err := p.Close()
	if err != nil {
		t.Fatal(err)
	}
	p = Poller{}
	_, _, err = p.Poll()
	if err != nil {
		t.Skipf("skipping due to poll error: %v", err)
	}
	err = p.Close()
	if err != nil {
		t.Fatal(err)
	}
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
	p.init()
	if p.initErr != nil {
		b.Skip(p.initErr)
	}
	b.Cleanup(func() { p.Close() })
	for range b.N {
		pl, err := p.getList()
		if err != nil {
			b.Fatal(err)
		}
		if incremental {
			p.prev = pl
		}
	}
}
