// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailnetdns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

type fakeGetter struct {
	mu  sync.Mutex
	cfg *tailcfg.DNSConfig
	err error
}

func (g *fakeGetter) DNSConfig(context.Context) (*tailcfg.DNSConfig, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg, g.err
}

func (g *fakeGetter) set(cfg *tailcfg.DNSConfig, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg, g.err = cfg, err
}

func TestRoutesFromDNSConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()
	cfg := &tailcfg.DNSConfig{
		Routes: map[string][]*dnstype.Resolver{
			"Corp.Internal.": {{Addr: "10.20.0.53"}, {Addr: "10.20.0.54:5353"}},
			"doh.example":    {{Addr: "https://dns.example/dns-query"}},
			"magic.example":  {},
			"mixed.example":  {{Addr: "https://dns.example/dns-query"}, {Addr: "fd7a:115c:a1e0::53"}},
			"bad..example":   {{Addr: "10.0.0.1"}},
		},
	}
	got := RoutesFromDNSConfig(cfg, logger)
	want := map[string][]netip.AddrPort{
		"corp.internal": {netip.MustParseAddrPort("10.20.0.53:53"), netip.MustParseAddrPort("10.20.0.54:5353")},
		"mixed.example": {netip.MustParseAddrPort("[fd7a:115c:a1e0::53]:53")},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for domain, addrs := range want {
		if g := got[domain]; len(g) != len(addrs) {
			t.Fatalf("routes[%q] = %v, want %v", domain, g, addrs)
		} else {
			for i := range addrs {
				if g[i] != addrs[i] {
					t.Errorf("routes[%q][%d] = %v, want %v", domain, i, g[i], addrs[i])
				}
			}
		}
	}
	if got := RoutesFromDNSConfig(nil, logger); len(got) != 0 {
		t.Errorf("nil config: got %v, want empty", got)
	}
}

func TestWatcher(t *testing.T) {
	logger := zap.NewNop().Sugar()
	getter := &fakeGetter{err: errors.New("no netmap")}
	w := NewWithInterval(getter, logger, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Start(ctx)
	}()

	expectNoEvent := func() {
		t.Helper()
		select {
		case <-w.Events():
			t.Fatal("unexpected event")
		case <-time.After(50 * time.Millisecond):
		}
	}
	expectEvent := func() {
		t.Helper()
		select {
		case <-w.Events():
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for an event")
		}
	}

	// Errors (no netmap yet) produce nothing.
	expectNoEvent()
	if w.Routes() != nil {
		t.Errorf("Routes() = %v before the first successful read, want nil", w.Routes())
	}

	// The first successful read is a change, even if there are no routes.
	getter.set(&tailcfg.DNSConfig{}, nil)
	expectEvent()
	if r := w.Routes(); r == nil || len(r) != 0 {
		t.Errorf("Routes() = %v, want empty non-nil map", r)
	}

	// Unchanged configuration: no further events.
	expectNoEvent()

	// A new route is a change.
	getter.set(&tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{"corp.internal": {{Addr: "10.20.0.53"}}}}, nil)
	expectEvent()
	r := w.Routes()
	if len(r["corp.internal"]) != 1 || r["corp.internal"][0] != netip.MustParseAddrPort("10.20.0.53:53") {
		t.Errorf("Routes() = %v", r)
	}
	// Mutating the returned map must not affect the watcher.
	delete(r, "corp.internal")
	if len(w.Routes()) != 1 {
		t.Error("Routes() returned the watcher's own map")
	}

	// A read error after a successful read keeps the last routes.
	getter.set(nil, errors.New("transient"))
	expectNoEvent()
	if len(w.Routes()) != 1 {
		t.Errorf("Routes() = %v after a transient error, want the previous routes", w.Routes())
	}

	cancel()
	<-done
}
