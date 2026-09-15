// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package portlist

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

// portFixture creates real sockets in the caller's network namespace.  The
// runner invokes this benchmark under `unshare -n`; no host routes or sockets
// are touched.  TCP pairs are accepted and held open, so the kernel has both
// LISTEN and ESTABLISHED entries while the poller runs.
type portFixture struct {
	closers   []net.Conn
	listeners []net.Listener
	packets   []net.PacketConn
	expected  map[uint16]bool
	mu        sync.Mutex
}

func (f *portFixture) close() {
	f.mu.Lock()
	closers := append([]net.Conn(nil), f.closers...)
	f.mu.Unlock()
	for _, c := range closers {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	}
	for _, ln := range f.listeners {
		_ = ln.Close()
	}
	for _, p := range f.packets {
		_ = p.Close()
	}
}

func makePortFixture(t testing.TB, pairs int) *portFixture {
	t.Helper()
	f := &portFixture{expected: map[uint16]bool{}}
	addTCP := func(network, listenAddr string) {
		ln, err := net.Listen(network, listenAddr)
		if err != nil {
			t.Skipf("%s unavailable: %v", network, err)
		}
		f.listeners = append(f.listeners, ln)
		f.expected[uint16(ln.Addr().(*net.TCPAddr).Port)] = true
		accepted := make(chan struct{}, pairs)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				f.mu.Lock()
				f.closers = append(f.closers, c)
				f.mu.Unlock()
				accepted <- struct{}{}
			}
		}()
		for i := 0; i < pairs; i++ {
			c, err := net.Dial(network, ln.Addr().String())
			if err != nil {
				t.Fatalf("dial %s: %v", network, err)
			}
			f.mu.Lock()
			f.closers = append(f.closers, c)
			f.mu.Unlock()
		}
		for i := 0; i < pairs; i++ {
			<-accepted
		}
	}
	addTCP("tcp4", "127.0.0.1:0")
	addTCP("tcp6", "[::1]:0")
	for _, network := range []string{"udp4", "udp6"} {
		for _, connected := range []bool{false, true} {
			addr := "0.0.0.0:0"
			peer := "127.0.0.1:9"
			if network == "udp6" {
				addr, peer = "[::]:0", "[::1]:9"
			}
			u, err := net.ListenPacket(network, addr)
			if err != nil {
				t.Skipf("%s unavailable: %v", network, err)
			}
			f.packets = append(f.packets, u)
			f.expected[uint16(u.LocalAddr().(*net.UDPAddr).Port)] = true
			if connected {
				c, err := net.Dial(network, peer)
				if err != nil {
					t.Fatalf("dial %s: %v", network, err)
				}
				f.closers = append(f.closers, c)
			}
		}
	}
	return f
}

func makeManyPortFixture(t testing.TB, pairs, extra int) *portFixture {
	f := makePortFixture(t, pairs)
	for i := 0; i < extra; i++ {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("extra listener: %v", err)
		}
		f.listeners = append(f.listeners, ln)
		f.expected[uint16(ln.Addr().(*net.TCPAddr).Port)] = true
	}
	return f
}

// pollerFor bypasses Poller's constructor so each implementation can be A/B'd
// in one process while retaining Poll's change detection and metadata path.
func pollerFor(impl osImpl) *Poller {
	p := &Poller{IncludeLocalhost: true, os: impl}
	p.initOnce.Do(func() {})
	return p
}

func BenchmarkPortlistBackends(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux-only")
	}
	maybeSkip(b)
	factories := []struct {
		name    string
		factory func(bool) *linuxImpl
	}{
		{"proc", func(include bool) *linuxImpl { return newLinuxImplWithDiag(include, false) }},
		{"diag", func(include bool) *linuxImpl { return newLinuxImplWithDiag(include, true) }},
	}
	// Run both orderings. This matters on a shared machine because the first
	// implementation can otherwise receive all cold page/cache effects.
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		for _, pairs := range []int{0, 100, 500} {
			for _, ix := range order {
				tc := factories[ix]
				b.Run(fmt.Sprintf("order%d/%s/pairs=%d", order[0], tc.name, pairs), func(b *testing.B) {
					f := makePortFixture(b, pairs)
					defer f.close()
					impl := tc.factory(true)
					if tc.name == "diag" {
						defer impl.Close()
						requireDiag(b, impl)
					}
					p := pollerFor(impl)
					defer p.Close()
					if _, _, err := p.Poll(); err != nil {
						b.Fatal(err)
					} // cold metadata pass
					b.ReportAllocs()
					var before, after syscall.Rusage
					syscall.Getrusage(syscall.RUSAGE_SELF, &before)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, _, err := p.Poll(); err != nil {
							b.Fatal(err)
						}
						if tc.name == "diag" && (impl.diagFD < 0 || impl.diagPermanent) {
							b.Fatal("diag benchmark fell back to proc")
						}
					}
					b.StopTimer()
					syscall.Getrusage(syscall.RUSAGE_SELF, &after)
					used := after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano()
					b.ReportMetric(float64(used)/float64(b.N), "cpu-ns/op")
				})
			}
		}
		for _, extra := range []int{16, 64} {
			for _, tc := range factories {
				b.Run(fmt.Sprintf("order%d/%s/listeners=%d", order[0], tc.name, extra), func(b *testing.B) {
					f := makeManyPortFixture(b, 0, extra)
					defer f.close()
					impl := tc.factory(true)
					if tc.name == "diag" {
						defer impl.Close()
						requireDiag(b, impl)
					}
					p := pollerFor(impl)
					defer p.Close()
					if _, _, err := p.Poll(); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, _, err := p.Poll(); err != nil {
							b.Fatal(err)
						}
						if tc.name == "diag" && (impl.diagFD < 0 || impl.diagPermanent) {
							b.Fatal("diag listener benchmark fell back to proc")
						}
					}
				})
			}
		}
	}
}

// Cold includes construction, the first kernel dump, and first process-name
// attribution. Fixture setup is outside the timer; each iteration constructs a
// fresh poller against the same fixed sockets.
func BenchmarkPortlistCold(b *testing.B) {
	maybeSkip(b)
	for _, tc := range []struct {
		name string
		diag bool
	}{{"proc", false}, {"diag", true}} {
		b.Run(tc.name, func(b *testing.B) {
			f := makePortFixture(b, 0)
			defer f.close()
			if tc.diag {
				func() {
					probe := newLinuxImplWithDiag(true, true)
					defer probe.Close()
					requireDiag(b, probe)
				}()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				impl := newLinuxImplWithDiag(true, tc.diag)
				p := pollerFor(impl)
				if _, _, err := p.Poll(); err != nil {
					b.Fatal(err)
				}
				if tc.diag && (impl.diagFD < 0 || impl.diagPermanent) {
					b.Fatal("diag cold benchmark fell back to proc")
				}
				p.Close()
			}
		})
	}
}

func TestPortlistBackendParity(t *testing.T) {
	maybeSkip(t)
	f := makePortFixture(t, 8)
	defer f.close()
	proc := pollerFor(newLinuxImplWithDiag(true, false))
	defer proc.Close()
	diagImpl := newLinuxImplWithDiag(true, true)
	defer diagImpl.Close()
	requireDiag(t, diagImpl)
	diag := pollerFor(diagImpl)
	defer diag.Close()
	a, _, err := proc.Poll()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := diag.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if diagImpl.diagFD < 0 || diagImpl.diagPermanent {
		t.Fatal("diag parity poll fell back to proc")
	}
	// A second pass exercises the warmed inode -> process metadata path. Poll
	// returns nil when unchanged, so retain the first result for comparison.
	if _, _, err = diag.Poll(); err != nil {
		t.Fatal(err)
	}
	stableFixture := func(in []Port) map[string]bool {
		out := map[string]bool{}
		for _, p := range in {
			if f.expected[p.Port] {
				out[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = true
			}
		}
		return out
	}
	if fmt.Sprint(stableFixture(a)) != fmt.Sprint(stableFixture(b)) {
		t.Fatalf("proc/diag mismatch: proc=%v diag=%v", stableFixture(a), stableFixture(b))
	}
	full := func(in []Port) map[string]Port {
		out := map[string]Port{}
		for _, p := range in {
			if f.expected[p.Port] {
				out[fmt.Sprintf("%s/%d", p.Proto, p.Port)] = p
			}
		}
		return out
	}
	for k, p := range full(a) {
		q, ok := full(b)[k]
		if !ok || p.Process != q.Process || p.Pid != q.Pid {
			t.Errorf("full parity %s: proc=%+v diag=%+v", k, p, q)
		}
		if p.Pid != os.Getpid() || p.Process != filepath.Base(os.Args[0]) {
			t.Errorf("unexpected fixture owner %s: %+v", k, p)
		}
	}
	if len(full(a)) != len(f.expected) {
		t.Fatalf("proc did not report every fixture socket: got %d want %d", len(full(a)), len(f.expected))
	}
}

func TestPortlistBackendChurn(t *testing.T) {
	maybeSkip(t)
	for _, diag := range []bool{false, true} {
		f := makePortFixture(t, 4)
		defer f.close()
		li := newLinuxImplWithDiag(true, diag)
		defer li.Close()
		if diag {
			requireDiag(t, li)
		}
		before, err := li.AppendListeningPorts(nil)
		if err != nil {
			t.Fatal(err)
		}
		if diag && (li.diagFD < 0 || li.diagPermanent) {
			t.Fatal("diag churn poll fell back to proc")
		}
		if len(before) == 0 {
			t.Fatal("empty initial listing")
		}
		_ = f.listeners[0].Close()
		after, err := li.AppendListeningPorts(nil)
		if err != nil {
			t.Fatal(err)
		}
		if diag && (li.diagFD < 0 || li.diagPermanent) {
			t.Fatal("diag churn poll fell back to proc")
		}
		if len(after) >= len(before) {
			t.Fatalf("churn did not remove listener: before=%d after=%d", len(before), len(after))
		}
	}
}
