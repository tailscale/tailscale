// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/usermetric"
)

// Concurrent requests from both clients must share one allocation.
func TestConcurrentAllocationRetries(t *testing.T) {
	deregisterMetrics()
	s, err := NewServer(t.Logf, 0, true, new(usermetric.Registry), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetStaticAddrPorts(views.SliceOf([]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.uc4Port)}))
	a, b := key.NewDisco().Public(), key.NewDisco().Public()
	type result struct {
		se  endpoint.ServerEndpoint
		err error
	}
	const requests = 32
	results := make(chan result, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			x, y := a, b
			if i%2 != 0 {
				x, y = y, x
			}
			se, err := s.AllocateEndpoint(x, y)
			results <- result{se, err}
		})
	}
	wg.Wait()
	close(results)
	var first endpoint.ServerEndpoint
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if first.ServerDisco.IsZero() {
			first = r.se
		}
		if r.se.ServerDisco != first.ServerDisco || r.se.VNI != first.VNI || r.se.LamportID != first.LamportID || r.se.ClientDisco != first.ClientDisco {
			t.Fatalf("retry created a different allocation: got %+v, first %+v", r.se, first)
		}
	}
	if got := len(s.GetSessions()); got != 1 {
		t.Fatalf("sessions = %d, want 1 for %d concurrent requests", got, requests)
	}
}

func TestAllocationRetryBindLifetime(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		bound bool
		fresh bool
	}{
		{name: "unbound", age: 10 * time.Second},
		{name: "expired-before-gc", age: defaultBindLifetime + time.Second, fresh: true},
		{name: "bound", age: defaultBindLifetime + time.Second, bound: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deregisterMetrics()
			s, err := NewServer(t.Logf, 0, true, new(usermetric.Registry), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s.SetStaticAddrPorts(views.SliceOf([]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.uc4Port)}))
			a, b := key.NewDisco().Public(), key.NewDisco().Public()
			first, err := s.AllocateEndpoint(a, b)
			if err != nil {
				t.Fatal(err)
			}

			// Advance the allocation's age without sleeping or waiting for GC.
			s.mu.Lock()
			e := s.serverEndpointByDisco[key.NewSortedPairOfDiscoPublic(a, b)]
			e.mu.Lock()
			e.allocatedAt = mono.Now().Add(-tc.age)
			allocatedAt := e.allocatedAt
			if tc.bound {
				e.boundAddrPorts = [2]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:10001"), netip.MustParseAddrPort("127.0.0.1:10002")}
				e.lastSeen = [2]mono.Time{mono.Now(), mono.Now()}
			}
			e.mu.Unlock()
			s.mu.Unlock()

			retry, err := s.AllocateEndpoint(b, a)
			if err != nil {
				t.Fatal(err)
			}
			if tc.fresh {
				if retry.VNI == first.VNI || retry.LamportID <= first.LamportID {
					t.Fatalf("expired allocation not replaced: first=%+v retry=%+v", first, retry)
				}
				if _, ok := s.serverEndpointByVNI.Load(first.VNI); ok {
					t.Fatal("expired VNI still registered")
				}
			} else {
				if retry.VNI != first.VNI || retry.LamportID != first.LamportID {
					t.Fatalf("live allocation changed: first=%+v retry=%+v", first, retry)
				}
				e.mu.Lock()
				got := e.allocatedAt
				e.mu.Unlock()
				if got != allocatedAt {
					t.Fatal("retry renewed the allocation's age")
				}
			}
			wantMax := defaultBindLifetime
			if !tc.fresh && !tc.bound {
				wantMax -= tc.age
			}
			if got := retry.BindLifetime.Duration; got <= 0 || got > wantMax {
				t.Fatalf("bind lifetime = %v, want in (0, %v]", got, wantMax)
			}
			if got := len(s.GetSessions()); got != 1 {
				t.Fatalf("sessions = %d, want 1", got)
			}
		})
	}
}
