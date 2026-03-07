// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestCheckDaemon(t *testing.T) {
	tests := []struct {
		name       string
		statusErr  error
		wantStatus checkStatus
	}{
		{
			name:       "running",
			statusErr:  nil,
			wantStatus: statusPass,
		},
		{
			name:       "unreachable",
			statusErr:  errors.New("dial unix: no such file or directory"),
			wantStatus: statusFail,
		},
		{
			name:       "permission denied",
			statusErr:  errors.New("permission denied"),
			wantStatus: statusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDaemon(tt.statusErr)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
		})
	}
}

func TestCheckAuth(t *testing.T) {
	tests := []struct {
		name         string
		backendState string
		wantStatus   checkStatus
	}{
		{name: "running", backendState: "Running", wantStatus: statusPass},
		{name: "needs login", backendState: "NeedsLogin", wantStatus: statusFail},
		{name: "stopped", backendState: "Stopped", wantStatus: statusFail},
		{name: "unknown state", backendState: "SomeWeirdState", wantStatus: statusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &ipnstate.Status{BackendState: tt.backendState}
			got := checkAuth(st, nil)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
		})
	}

	t.Run("daemon unreachable", func(t *testing.T) {
		got := checkAuth(nil, errors.New("unreachable"))
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})
}

func TestCheckKeyExpiry(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	almostExpired := time.Now().Add(2 * 24 * time.Hour)
	soonish := time.Now().Add(10 * 24 * time.Hour)
	farFuture := time.Now().Add(60 * 24 * time.Hour)

	tests := []struct {
		name       string
		expiry     *time.Time
		wantStatus checkStatus
	}{
		{name: "no expiry (tagged device)", expiry: nil, wantStatus: statusPass},
		{name: "expired", expiry: &past, wantStatus: statusFail},
		{name: "expiring within 3 days", expiry: &almostExpired, wantStatus: statusFail},
		{name: "expiring within 14 days", expiry: &soonish, wantStatus: statusWarn},
		{name: "far future", expiry: &farFuture, wantStatus: statusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &ipnstate.Status{
				Self: &ipnstate.PeerStatus{KeyExpiry: tt.expiry},
			}
			got := checkKeyExpiry(st, nil)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
		})
	}

	t.Run("daemon unreachable", func(t *testing.T) {
		got := checkKeyExpiry(nil, errors.New("unreachable"))
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})
}

func TestCheckSubnetRoutes(t *testing.T) {
	routes := views.SliceOf([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	})

	t.Run("no routes configured", func(t *testing.T) {
		st := &ipnstate.Status{Self: &ipnstate.PeerStatus{}}
		got := checkSubnetRoutes(st, nil)
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})

	t.Run("routes advertised", func(t *testing.T) {
		st := &ipnstate.Status{
			Self: &ipnstate.PeerStatus{PrimaryRoutes: &routes},
		}
		got := checkSubnetRoutes(st, nil)
		if got.Status != statusPass {
			t.Errorf("status = %q, want %q (message: %s)", got.Status, statusPass, got.Message)
		}
	})

	t.Run("daemon unreachable", func(t *testing.T) {
		got := checkSubnetRoutes(nil, errors.New("unreachable"))
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})
}

func TestCheckExitNode(t *testing.T) {
	t.Run("no exit node", func(t *testing.T) {
		st := &ipnstate.Status{}
		got := checkExitNode(st, nil)
		if got.Status != statusPass {
			t.Errorf("status = %q, want %q", got.Status, statusPass)
		}
	})

	t.Run("exit node active", func(t *testing.T) {
		peer := &ipnstate.PeerStatus{
			HostName:     "exit-node-host",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
			ExitNode:     true,
		}
		st := &ipnstate.Status{
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				key.NodePublic{}: peer,
			},
		}
		got := checkExitNode(st, nil)
		if got.Status != statusPass {
			t.Errorf("status = %q, want %q (message: %s)", got.Status, statusPass, got.Message)
		}
	})

	t.Run("daemon unreachable", func(t *testing.T) {
		got := checkExitNode(nil, errors.New("unreachable"))
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})
}

func TestCheckVersion(t *testing.T) {
	t.Run("version present", func(t *testing.T) {
		st := &ipnstate.Status{Version: "1.80.0-dev20260307"}
		got := checkVersion(st, nil)
		if got.Status != statusPass {
			t.Errorf("status = %q, want %q", got.Status, statusPass)
		}
	})

	t.Run("daemon unreachable", func(t *testing.T) {
		got := checkVersion(nil, errors.New("unreachable"))
		if got.Status != statusSkip {
			t.Errorf("status = %q, want %q", got.Status, statusSkip)
		}
	})
}
