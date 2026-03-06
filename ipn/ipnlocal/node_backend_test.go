// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/filter"
)

func TestNodeBackendReadiness(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

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
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

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
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	shutdownCause := errors.New("test shutdown")
	nb.shutdown(shutdownCause)
	nb.ready() // Calling ready after shutdown is a no-op, but should not panic, etc.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
}

func TestNodeBackendParentContextCancellation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	nb := newNodeBackend(ctx, tstest.WhileTestRunningLogger(t), eventbus.New())

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
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	// Calling [nodeBackend.ready] and [nodeBackend.shutdown] concurrently
	// should not cause issues, and [nodeBackend.Wait] should unblock,
	// but the result of [nodeBackend.Wait] is intentionally undefined.
	go nb.ready()
	go nb.shutdown(errors.New("test shutdown"))

	nb.Wait(context.Background())
}

func TestPeerCapsIncludesServiceVIPs(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	nodeIP := netip.MustParseAddr("100.64.1.1")
	svcIP := netip.MustParseAddr("100.124.180.147")
	peerIP := netip.MustParseAddr("100.64.2.2")

	// One grant targets the node IP, one targets the service VIP.
	mm, err := filter.MatchesFromFilterRules([]tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.2.0/24"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
				Caps: []tailcfg.PeerCapability{"node-scoped-cap"},
			}},
		},
		{
			SrcIPs: []string{"100.64.2.0/24"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts:   []netip.Prefix{netip.MustParsePrefix("100.124.180.147/32")},
				Caps:   []tailcfg.PeerCapability{"svc-scoped-cap"},
				CapMap: tailcfg.PeerCapMap{"svc-scoped-cap": {tailcfg.RawMessage(`{"routes":["/test/*"]}`)}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	filt := filter.New(mm, nil, nil, &netipx.IPSet{}, nil, t.Logf)
	nb.filterAtomic.Store(filt)

	// Set up the netmap with service VIP mappings.
	svcMappings := tailcfg.ServiceIPMappings{
		"svc:http": {svcIP},
	}
	svcMappingsJSON, err := json.Marshal(svcMappings)
	if err != nil {
		t.Fatal(err)
	}

	nb.netMap = &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.PrefixFrom(nodeIP, 32)},
			CapMap: tailcfg.NodeCapMap{
				tailcfg.NodeAttrServiceHost: {tailcfg.RawMessage(svcMappingsJSON)},
			},
		}).View(),
	}

	caps := nb.PeerCaps(peerIP)
	if caps == nil {
		t.Fatal("PeerCaps returned nil")
	}
	if !caps.HasCapability("node-scoped-cap") {
		t.Error("missing node-scoped-cap")
	}
	if !caps.HasCapability("svc-scoped-cap") {
		t.Error("missing svc-scoped-cap — service VIP caps not included in PeerCaps")
	}

	vals := caps["svc-scoped-cap"]
	if len(vals) == 0 {
		t.Fatal("svc-scoped-cap has no values")
	}
}

func TestPeerCapsNodeOnlyWithoutServiceVIPs(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	nodeIP := netip.MustParseAddr("100.64.1.1")
	peerIP := netip.MustParseAddr("100.64.2.2")

	mm, err := filter.MatchesFromFilterRules([]tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.2.0/24"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
				Caps: []tailcfg.PeerCapability{"basic-cap"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	filt := filter.New(mm, nil, nil, &netipx.IPSet{}, nil, t.Logf)
	nb.filterAtomic.Store(filt)

	nb.netMap = &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.PrefixFrom(nodeIP, 32)},
		}).View(),
	}

	caps := nb.PeerCaps(peerIP)
	if !caps.HasCapability("basic-cap") {
		t.Error("missing basic-cap")
	}
}

func TestNodeBackendReachability(t *testing.T) {
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

		peer tailcfg.Node
		want bool
	}{
		{
			name: "disabled/offline",
			cap:  false,
			peer: tailcfg.Node{
				Online: ptr.To(false),
			},
			want: false,
		},
		{
			name: "disabled/online",
			cap:  false,
			peer: tailcfg.Node{
				Online: ptr.To(true),
			},
			want: true,
		},
		{
			name: "enabled/offline",
			cap:  true,
			peer: tailcfg.Node{
				Online: ptr.To(false),
			},
			want: true,
		},
		{
			name: "enabled/online",
			cap:  true,
			peer: tailcfg.Node{
				Online: ptr.To(true),
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())
			nb.netMap = &netmap.NetworkMap{}
			if tc.cap {
				nb.netMap.AllCaps.Make()
				nb.netMap.AllCaps.Add(tailcfg.NodeAttrClientSideReachability)
			}

			got := nb.PeerIsReachable(t.Context(), tc.peer.View())
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
