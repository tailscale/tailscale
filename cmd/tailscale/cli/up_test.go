// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"flag"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/util/set"
)

// validUpFlags are the only flags that are valid for tailscale up. The up
// command is frozen: no new preferences can be added. Instead, add them to
// tailscale set.
// See tailscale/tailscale#15460.
var validUpFlags = set.Of(
	"accept-dns",
	"accept-risk",
	"accept-routes",
	"advertise-connector",
	"advertise-exit-node",
	"advertise-routes",
	"advertise-tags",
	"auth-key",
	"exit-node",
	"exit-node-allow-lan-access",
	"force-reauth",
	"host-routes",
	"hostname",
	"json",
	"login-server",
	"netfilter-mode",
	"nickname",
	"operator",
	"report-posture",
	"qr",
	"qr-format",
	"reset",
	"shields-up",
	"snat-subnet-routes",
	"ssh",
	"stateful-filtering",
	"timeout",
	"unattended",
	"client-id",
	"client-secret",
	"id-token",
	"audience",
)

// TestUpFlagSetIsFrozen complains when new flags are added to tailscale up.
func TestUpFlagSetIsFrozen(t *testing.T) {
	upFlagSet.VisitAll(func(f *flag.Flag) {
		name := f.Name
		if !validUpFlags.Contains(name) {
			t.Errorf("--%s flag added to tailscale up, new prefs go in tailscale set: see tailscale/tailscale#15460", name)
		}
	})
}

// Route filters are set-only preferences. They must survive both ways up
// changes prefs (EditPrefs while running and Start while stopped or reauthing),
// unless the user explicitly resets their settings.
func TestUpPreservesSubnetRouteFilters(t *testing.T) {
	for _, state := range []string{"Running", "Stopped"} {
		for _, mode := range []string{"up", "force-reauth", "reset"} {
			t.Run(state+"/"+mode, func(t *testing.T) {
				old := ipn.NewPrefs()
				old.ControlURL = ipn.DefaultControlURL
				old.RouteAll = true
				old.AcceptRoutesAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
				old.AcceptRoutesDeny = []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")}
				env := upCheckEnv{goos: "linux", backendState: state}
				env.flagSet = newUpFlagSet(env.goos, &env.upArgs, "up")
				args := []string{"--accept-routes=true", "--accept-risk=lose-ssh"}
				if mode != "up" {
					args = append(args, "--"+mode)
				}
				if err := env.flagSet.Parse(args); err != nil {
					t.Fatal(err)
				}
				next, err := prefsFromUpArgs(env.upArgs, t.Logf, new(ipnstate.Status), env.goos)
				if err != nil {
					t.Fatal(err)
				}
				_, mp, err := updatePrefs(next, old, env)
				if err != nil {
					t.Fatal(err)
				}
				wantEdit := state == "Running" && mode != "force-reauth"
				if (mp != nil) != wantEdit {
					t.Fatalf("EditPrefs path = %v, want %v", mp != nil, wantEdit)
				}
				if mp != nil {
					next = old.Clone()
					next.ApplyEdits(mp)
				}
				if mode == "reset" {
					if len(next.AcceptRoutesAllow) != 0 || len(next.AcceptRoutesDeny) != 0 {
						t.Fatalf("reset retained filters: allow=%v deny=%v", next.AcceptRoutesAllow, next.AcceptRoutesDeny)
					}
				} else if !slices.Equal(next.AcceptRoutesAllow, old.AcceptRoutesAllow) || !slices.Equal(next.AcceptRoutesDeny, old.AcceptRoutesDeny) {
					t.Fatalf("up changed filters: allow=%v deny=%v", next.AcceptRoutesAllow, next.AcceptRoutesDeny)
				}
			})
		}
	}
}
