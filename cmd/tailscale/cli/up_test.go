// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"flag"
	"testing"

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
