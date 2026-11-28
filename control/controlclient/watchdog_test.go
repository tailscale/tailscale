// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
)

// blackholeConn is a net.Conn that can be made to behave like a TCP
// connection whose upstream NAT mapping was flushed: writes appear to
// succeed, reads never return data, and no RST or FIN ever arrives.
type blackholeConn struct {
	net.Conn
	dead      atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}

	// onSwallow, if non-nil, is called for each write swallowed while dead.
	onSwallow func()
}

func (c *blackholeConn) Read(p []byte) (int, error) {
	if c.dead.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(p)
	if c.dead.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *blackholeConn) Write(p []byte) (int, error) {
	if c.dead.Load() {
		if c.onSwallow != nil {
			c.onSwallow()
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *blackholeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestMapWatchdogRedialsBlackholedConn verifies that after the map watchdog
// fires on a connection that silently stopped delivering packets (as after an
// ISP reconnect that assigns a new public IP), the next map request dials a
// fresh control connection instead of reusing the dead one.
// See tailscale/tailscale#12021.
func TestMapWatchdogRedialsBlackholedConn(t *testing.T) {
	var (
		mu    sync.Mutex
		conns []*blackholeConn

		swallowOnce sync.Once
		swallowed   = make(chan struct{}) // closed on first swallowed write
	)
	numDials := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(conns)
	}
	d := newDirectForTestControlWithConnHook(t, &testcontrol.Server{}, func(c net.Conn) net.Conn {
		bc := &blackholeConn{
			Conn:      c,
			closed:    make(chan struct{}),
			onSwallow: func() { swallowOnce.Do(func() { close(swallowed) }) },
		}
		mu.Lock()
		conns = append(conns, bc)
		mu.Unlock()
		return bc
	})
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Now()})
	d.clock = clock

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := d.TryLogin(ctx, LoginEphemeral); err != nil {
		t.Fatalf("TryLogin: %v", err)
	}
	if _, err := d.FetchNetMapForTest(ctx); err != nil {
		t.Fatalf("initial FetchNetMapForTest: %v", err)
	}

	// Upstream NAT change: every existing control connection goes silent.
	mu.Lock()
	for _, c := range conns {
		c.dead.Store(true)
	}
	mu.Unlock()
	dialsBefore := numDials()

	// The map request on the dead connection hangs until the watchdog fires.
	errc := make(chan error, 1)
	go func() {
		_, err := d.FetchNetMapForTest(ctx)
		errc <- err
	}()
	// sendMapRequest arms the watchdog before it sends the request, so once
	// the request's first write is swallowed, a single advance fires it.
	select {
	case <-swallowed:
	case err := <-errc:
		t.Fatalf("map request returned before reaching the dead connection: %v", err)
	case <-ctx.Done():
		t.Fatal("map request never wrote to the dead connection")
	}
	clock.Advance(watchdogTimeout + time.Second)
	var err error
	select {
	case err = <-errc:
	case <-ctx.Done():
		t.Fatal("map request on blackholed connection never returned")
	}
	if err == nil {
		t.Fatal("map request on blackholed connection unexpectedly succeeded")
	}

	// The network path itself is fine again; only the old connection is dead.
	// Without advancing the clock, the next request must succeed promptly.
	fetchCtx, fetchCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer fetchCancel()
	if _, err := d.FetchNetMapForTest(fetchCtx); err != nil {
		t.Fatalf("FetchNetMapForTest after watchdog: %v (dials=%d, before blackhole=%d)", err, numDials(), dialsBefore)
	}
	if got := numDials(); got <= dialsBefore {
		t.Errorf("dials = %d; want a new connection after watchdog (had %d)", got, dialsBefore)
	}
}
