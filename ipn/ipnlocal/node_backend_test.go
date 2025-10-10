// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/eventbus"
)

func TestNodeBackendReadiness(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New(), nil)

	// The node backend is not ready until [nodeBackend.ready] is called,
	// and [nodeBackend.Wait] should fail with [context.DeadlineExceeded].
	ctx, cancelCtx := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelCtx()
	if err := nb.Wait(ctx); err != ctx.Err() {
		t.Fatalf("Wait: got %v; want %v", err, ctx.Err())
	}

	// Start a goroutine to wait for the node backend to become ready.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != nil {
			t.Errorf("Wait: got %v; want nil", err)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.ready] to indicate that the node backend is now ready.
	go nb.ready()

	// Once the backend is called, [nodeBackend.Wait] should return immediately without error.
	if err := nb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: got %v; want nil", err)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New(), nil)

	shutdownCause := errors.New("test shutdown")

	// Start a goroutine to wait for the node backend to become ready.
	// This test expects it to block until the node backend shuts down
	// and then return the specified shutdown cause.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != shutdownCause {
			t.Errorf("Wait: got %v; want %v", err, shutdownCause)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.shutdown] to indicate that the node backend is shutting down.
	nb.shutdown(shutdownCause)

	// Calling it again is fine, but should not change the shutdown cause.
	nb.shutdown(errors.New("test shutdown again"))

	// After shutdown, [nodeBackend.Wait] should return with the specified shutdown cause.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
	// The context associated with the node backend should also be cancelled
	// and its cancellation cause should match the shutdown cause.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
	if cause := context.Cause(nb.Context()); cause != shutdownCause {
		t.Fatalf("Cause: got %v; want %v", cause, shutdownCause)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendReadyAfterShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New(), nil)

	shutdownCause := errors.New("test shutdown")
	nb.shutdown(shutdownCause)
	nb.ready() // Calling ready after shutdown is a no-op, but should not panic, etc.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
}

func TestNodeBackendParentContextCancellation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	nb := newNodeBackend(ctx, tstest.WhileTestRunningLogger(t), eventbus.New(), nil)

	cancelCtx()

	// Cancelling the parent context should cause [nodeBackend.Wait]
	// to return with [context.Canceled].
	if err := nb.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait: got %v; want %v", err, context.Canceled)
	}

	// And the node backend's context should also be cancelled.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
}

func TestNodeBackendConcurrentReadyAndShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New(), nil)

	// Calling [nodeBackend.ready] and [nodeBackend.shutdown] concurrently
	// should not cause issues, and [nodeBackend.Wait] should unblock,
	// but the result of [nodeBackend.Wait] is intentionally undefined.
	go nb.ready()
	go nb.shutdown(errors.New("test shutdown"))

	nb.Wait(context.Background())
}

func TestNodeBackendReachability(t *testing.T) {
	addrs := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}
	defaults := func(n tailcfg.Node) tailcfg.Node {
		if n.ID == 0 {
			n.ID = 1234
		}
		if n.Name == "" {
			n.Name = "exit-node.example.ts.net"
		}
		return n
	}

	for _, tc := range []struct {
		name string

		// Cap sets [tailcfg.NodeAttrClientSideReachability] on the self
		// node.
		//
		// When disabled, the client relies on the control plane sending
		// an accurate peer.Online flag. When enabled, the client
		// ignores peer.Online and determines whether it can reach the
		// peer node.
		cap bool

		// Peer defines the peer node.
		peer tailcfg.Node

		// Ping sets how the peer node responds to pings:
		// pingTimedOut: peer is unreachable
		// pingSuccess: peer responds to pings
		// pingLocalhost: peer is the same as the self node
		ping mockPinger

		want bool
	}{
		{
			name: "disabled/nil",
			cap:  false,
			peer: defaults(tailcfg.Node{
				Online: nil,
			}),
			want: false,
		},
		{
			name: "disabled/offline",
			cap:  false,
			peer: defaults(tailcfg.Node{
				Online: ptr.To(false),
			}),
			want: false,
		},
		{
			name: "disabled/online",
			cap:  false,
			peer: defaults(tailcfg.Node{
				Online: ptr.To(true),
			}),
			want: true,
		},
		{
			name: "enabled/no_ip",
			cap:  true,
			ping: pingTimedOut,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(false),
				Addresses: nil,
			}),
			want: false,
		},
		{
			name: "enabled/offline",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(false),
				Addresses: addrs,
			}),
			ping: pingTimedOut,
			want: false,
		},
		{
			name: "enabled/offline_but_pingable",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(false),
				Addresses: addrs,
			}),
			ping: pingSuccess,
			want: true,
		},
		{
			name: "enabled/online",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(true),
				Addresses: addrs,
			}),
			ping: pingSuccess,
			want: true,
		},
		{
			name: "enabled/online_but_unpingable",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(true),
				Addresses: addrs,
			}),
			ping: pingTimedOut,
			want: false,
		},
		{
			name: "enabled/offline_localhost",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(false),
				Addresses: addrs,
			}),
			ping: pingLocalhost,
			want: true,
		},
		{
			name: "enabled/online_localhost",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(true),
				Addresses: addrs,
			}),
			ping: pingLocalhost,
			want: true,
		},
		{
			name: "enabled/offline_but_cancelled",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(false),
				Addresses: addrs,
			}),
			ping: pingCancelled,
			want: false,
		},
		{
			name: "enabled/online_but_cancelled",
			cap:  true,
			peer: defaults(tailcfg.Node{
				Online:    ptr.To(true),
				Addresses: addrs,
			}),
			ping: pingCancelled,
			want: false,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			nb := newNodeBackend(ctx, tstest.WhileTestRunningLogger(t), eventbus.New(), mockPinger(tc.ping))
			nb.netMap = &netmap.NetworkMap{}
			if tc.cap {
				nb.netMap.AllCaps.Make()
				nb.netMap.AllCaps.Add(tailcfg.NodeAttrClientSideReachability)
			}

			if tc.ping == pingCancelled {
				c, cancel := context.WithCancelCause(ctx)
				ctx = c
				cancel(fmt.Errorf("subtest: %q", tc.name))
			}

			got := nb.PeerIsReachable(ctx, tc.peer.View())
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

type mockPinger int

const (
	pingTimedOut mockPinger = iota
	pingSuccess
	pingLocalhost
	pingCancelled
)

func (p mockPinger) Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, size int) (*ipnstate.PingResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	res := &ipnstate.PingResult{
		IP:     ip.String(),
		NodeIP: ip.String(),
	}
	switch p {
	case pingTimedOut:
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()
		<-ctx.Done()
		res.Err = ctx.Err().Error()
		return res, nil
	case pingLocalhost:
		res.Err = fmt.Sprintf("%v is local Tailscale IP", ip)
		res.IsLocalIP = true
	case pingSuccess:
		res.LatencySeconds = 1
	default:
		panic(fmt.Sprintf("unknown mockPinger %v", p))
	}
	return res, nil
}
