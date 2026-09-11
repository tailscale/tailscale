// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
)

type userProfileUpdateObserver struct{}

func (userProfileUpdateObserver) SetControlClientStatus(Client, Status) {}

func (userProfileUpdateObserver) UpdateUserProfiles(map[tailcfg.UserID]tailcfg.UserProfileView) bool {
	return true
}

func TestMapRoutineStateUpdateUserProfilesConcurrentCancelMapCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Auto{
		logf:      func(string, ...any) {},
		observer:  userProfileUpdateObserver{},
		mapCtx:    ctx,
		mapCancel: cancel,
		loggedIn:  true,
		inMapPoll: true,
	}
	mrs := mapRoutineState{c: c}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			<-start
			for range 2000 {
				c.mu.Lock()
				c.cancelMapCtxLocked()
				c.mu.Unlock()
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			<-start
			for range 2000 {
				mrs.UpdateUserProfiles(nil)
			}
		})
	}

	close(start)
	wg.Wait()

	waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.observerQueue.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	c.observerQueue.Shutdown()
	c.mapCancel()
}

func TestSTUNEndpointIPChange(t *testing.T) {
	stun := func(addr string) tailcfg.Endpoint {
		return tailcfg.Endpoint{
			Addr: netip.MustParseAddrPort(addr),
			Type: tailcfg.EndpointSTUN,
		}
	}
	local := func(addr string) tailcfg.Endpoint {
		return tailcfg.Endpoint{
			Addr: netip.MustParseAddrPort(addr),
			Type: tailcfg.EndpointLocal,
		}
	}

	c := new(Auto)
	tests := []struct {
		name      string
		endpoints []tailcfg.Endpoint
		want      bool
	}{
		{"local-only", []tailcfg.Endpoint{local("192.0.2.10:41641")}, false},
		{"initial", []tailcfg.Endpoint{stun("198.51.100.10:41641")}, false},
		{"new-port", []tailcfg.Endpoint{stun("198.51.100.10:51234")}, false},
		{"IPv6-only", []tailcfg.Endpoint{stun("[2001:db8::10]:41641")}, false},
		{"new-IP", []tailcfg.Endpoint{
			stun("198.51.100.10:51234"),
			stun("203.0.113.20:42345"),
		}, true},
		{"same-IPs", []tailcfg.Endpoint{
			stun("198.51.100.10:59999"),
			stun("203.0.113.20:42999"),
		}, false},
		{"remove-old-IP", []tailcfg.Endpoint{stun("203.0.113.20:42999")}, false},
		{"empty", nil, false},
		{"new-IP-after-empty", []tailcfg.Endpoint{
			stun("192.0.2.30:41641"),
			stun("203.0.113.20:42999"),
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.noteSTUNEndpointIPs(tt.endpoints); got != tt.want {
				t.Errorf("noteSTUNEndpointIPs = %v, want %v", got, tt.want)
			}
		})
	}

	c.closed = true
	if c.noteSTUNEndpointIPs([]tailcfg.Endpoint{stun("192.0.2.31:41641")}) {
		t.Error("closed client requested a reset")
	}
}

type closeRecorder struct {
	closed atomic.Bool
}

func (*closeRecorder) RoundTrip(*http.Request) (*http.Response, error) {
	panic("unexpected RoundTrip")
}

func (r *closeRecorder) CloseIdleConnections() {
	r.closed.Store(true)
}

// Regression test for the WAN-failover case in tailscale/tailscale#12021:
// finding a new STUN IP must replace the cached Noise client even while paused.
func TestUpdateEndpointsResetsNoiseClientOnNewSTUNIP(t *testing.T) {
	stun := func(addr string) tailcfg.Endpoint {
		return tailcfg.Endpoint{
			Addr: netip.MustParseAddrPort(addr),
			Type: tailcfg.EndpointSTUN,
		}
	}

	tr := new(closeRecorder)
	nc := &ts2021.Client{Client: &http.Client{Transport: tr}}
	d := &Direct{logf: t.Logf, noiseClient: nc}
	oldMapCtx, oldMapCancel := context.WithCancel(t.Context())
	c := &Auto{
		direct:    d,
		logf:      t.Logf,
		updateCh:  make(chan struct{}, 1),
		mapCtx:    oldMapCtx,
		mapCancel: oldMapCancel,
		paused:    true,
	}
	t.Cleanup(func() { c.mapCancel() })
	drainUpdate := func() {
		t.Helper()
		select {
		case <-c.updateCh:
		default:
			t.Fatal("control update was not queued")
		}
	}

	c.UpdateEndpoints([]tailcfg.Endpoint{stun("198.51.100.10:41641")})
	drainUpdate()
	c.UpdateEndpoints([]tailcfg.Endpoint{stun("198.51.100.10:51234")})
	drainUpdate()
	if tr.closed.Load() {
		t.Fatal("port-only change closed the Noise client")
	}

	c.UpdateEndpoints([]tailcfg.Endpoint{
		stun("198.51.100.10:51234"),
		stun("203.0.113.20:42345"),
	})

	select {
	case <-oldMapCtx.Done():
	default:
		t.Error("old map context was not canceled")
	}
	select {
	case <-c.mapCtx.Done():
		t.Error("new map context is already canceled")
	default:
	}
	if !tr.closed.Load() {
		t.Error("old Noise client was not closed")
	}
	if d.noiseClient != nil {
		t.Error("old Noise client was retained")
	}
	if got := len(c.updateCh); got != 1 {
		t.Errorf("queued updates = %d, want 1", got)
	}
}
