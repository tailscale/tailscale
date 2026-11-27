// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// TestAcceptSubnetRouteFilters exercises CLI configuration, control updates,
// persistence, and WireGuard routing with two real userspace-networking nodes.
// TSMP probes reach the subnet router without needing a physical subnet or
// changing the host's routes. Unlike discovery pings, they use the destination
// address in an IP packet and therefore require an installed WireGuard route.
func TestAcceptSubnetRouteFilters(t *testing.T) {
	tstest.Parallel(t)
	env := NewTestEnv(t)

	routes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8:2::/64"),
		netip.MustParsePrefix("2001:db8:30::/64"),
	}
	var routeArgs []string
	for _, p := range routes {
		routeArgs = append(routeArgs, p.String())
	}
	router := NewTestNode(t, env, TUNMode(false))
	routerDaemon := router.StartDaemon()
	defer routerDaemon.MustCleanShutdown(t)
	router.AwaitListening()
	router.MustUp("--advertise-routes=" + strings.Join(routeArgs, ","))
	router.AwaitRunning()
	routerKey := router.MustStatus().Self.PublicKey
	env.Control.SetSubnetRoutes(routerKey, routes)

	client := NewTestNode(t, env, TUNMode(false))
	clientDaemon := client.StartDaemon()
	defer func() { clientDaemon.MustCleanShutdown(t) }()
	client.AwaitListening()
	client.MustUp("--accept-routes=true")
	client.AwaitRunning()

	peerIPs := []netip.Addr{router.AwaitIP4(), router.AwaitIP6()}
	targets := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("2001:db8:2::1"),
		netip.MustParseAddr("2001:db8:30::1"),
	}
	ping := func(t *testing.T, ip netip.Addr) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		res, err := client.LocalClient().Ping(ctx, ip, tailcfg.PingTSMP)
		if err != nil {
			return err
		}
		if res.Err != "" {
			return errors.New(res.Err)
		}
		return nil
	}
	checkReachable := func(t *testing.T, ip netip.Addr) {
		t.Helper()
		if err := tstest.WaitFor(10*time.Second, func() error { return ping(t, ip) }); err != nil {
			t.Fatalf("TSMP ping %v: %v", ip, err)
		}
	}

	for _, tt := range []struct {
		name         string
		args         []string
		want         [4]bool // indexed by targets
		wantError    bool
		updateRoutes bool
		restart      bool
		stop         bool
	}{
		{
			name: "unfiltered",
			want: [4]bool{true, true, true, true},
		},
		{
			name: "deny",
			args: []string{"set", "--accept-routes-deny=192.0.2.0/24,2001:db8:2::/64"},
			want: [4]bool{false, true, false, true},
		},
		{
			name:         "control_update",
			updateRoutes: true,
			want:         [4]bool{false, true, false, true},
		},
		{
			name: "allow",
			args: []string{"set", "--accept-routes-allow=198.51.100.0/24,2001:db8:30::/48", "--accept-routes-deny="},
			want: [4]bool{false, true, false, true},
		},
		{
			// The valid allow change must not take effect when the deny list
			// in the same command contains a non-canonical prefix.
			name:      "invalid_filter_is_atomic",
			args:      []string{"set", "--accept-routes-allow=192.0.2.0/24", "--accept-routes-deny=192.0.2.1/24"},
			wantError: true,
			want:      [4]bool{false, true, false, true},
		},
		{
			// Neither target is inside the denied prefix. The entire advertised
			// route must be excluded, even for a partial deny overlap.
			name: "deny_overlap_overrides_allow",
			args: []string{"set", "--accept-routes-deny=198.51.100.128/25,2001:db8:30:0:8000::/65"},
		},
		{
			// Both lists are needed to exclude all four destinations. Losing
			// either list on restart would make two destinations reachable.
			name:    "restart",
			restart: true,
		},
		{
			name: "running_up_preserves_filters",
			args: []string{"up", "--accept-routes=true", "--login-server=" + env.ControlURL()},
		},
		{
			name: "stopped_up_preserves_filters",
			args: []string{"up", "--accept-routes=true", "--login-server=" + env.ControlURL()},
			stop: true,
		},
		{
			name: "clear",
			args: []string{"set", "--accept-routes-allow=", "--accept-routes-deny="},
			want: [4]bool{true, true, true, true},
		},
		{
			name: "disable",
			args: []string{"set", "--accept-routes=false"},
		},
		{
			name: "reenable",
			args: []string{"set", "--accept-routes=true"},
			want: [4]bool{true, true, true, true},
		},
		{
			name: "filters_before_reset",
			args: []string{"set", "--accept-routes-allow=198.51.100.0/24,2001:db8:30::/48", "--accept-routes-deny=198.51.100.0/24,2001:db8:30::/64"},
		},
		{
			name: "reset_clears_filters",
			args: []string{"up", "--reset", "--accept-routes=true", "--login-server=" + env.ControlURL()},
			want: [4]bool{true, true, true, true},
		},
	} {
		if !t.Run(tt.name, func(t *testing.T) {
			if tt.stop {
				if out, err := client.TailscaleForOutput("down").CombinedOutput(); err != nil {
					t.Fatalf("tailscale down: %v\n%s", err, out)
				}
				client.AwaitBackendState("Stopped")
			}
			if len(tt.args) != 0 {
				out, err := client.TailscaleForOutput(tt.args...).CombinedOutput()
				if (err != nil) != tt.wantError {
					t.Fatalf("tailscale %v: %v (want error: %v)\n%s", tt.args, err, tt.wantError, out)
				}
			}
			if tt.updateRoutes {
				// Control replaces the denied routes with more specific ones.
				// The filter must also apply when processing a new network map.
				updated := append([]netip.Prefix(nil), routes...)
				updated[0] = netip.MustParsePrefix("192.0.2.0/25")
				updated[2] = netip.MustParsePrefix("2001:db8:2::/65")
				env.Control.SetSubnetRoutes(routerKey, updated)
				if err := tstest.WaitFor(10*time.Second, func() error {
					p := client.MustStatus().Peer[routerKey]
					if p == nil || p.AllowedIPs == nil {
						return errors.New("subnet router is not in the network map")
					}
					for _, prefix := range p.AllowedIPs.All() {
						if prefix == updated[0] {
							return nil
						}
					}
					return fmt.Errorf("waiting for route update: %v", p.AllowedIPs)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.restart {
				clientDaemon.MustCleanShutdown(t)
				clientDaemon = client.StartDaemon()
				client.AwaitListening()
				client.AwaitRunning()
			}
			// Confirm the peer remains healthy before checking negative probes.
			for _, ip := range peerIPs {
				checkReachable(t, ip)
			}
			for i, ip := range targets {
				if tt.want[i] {
					checkReachable(t, ip)
				} else if err := ping(t, ip); err == nil {
					t.Errorf("TSMP ping %v succeeded through an excluded subnet route", ip)
				} else if err.Error() != "no matching peer" {
					t.Errorf("TSMP ping %v: %v; want no matching peer", ip, err)
				}
			}
		}) {
			// These subtests model successive changes to one client's settings.
			t.FailNow()
		}
	}
}
