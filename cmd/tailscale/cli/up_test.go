// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"flag"
	"runtime"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/persist"
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
	"auth-exchange-attempts",
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

// TestUpdatePrefsSSHToggleRisk verifies that a bare "tailscale up" run over
// Tailscale SSH does not warn about disconnecting the session, since a simple
// up never changes RunSSH. A real SSH toggle must still warn.
func TestUpdatePrefsSSHToggleRisk(t *testing.T) {
	oldGetSSHClient := getSSHClientEnvVar
	t.Cleanup(func() { getSSHClientEnvVar = oldGetSSHClient })
	getSSHClientEnvVar = func() string { return "100.64.0.1 51234 22" }

	newCurPrefs := func() *ipn.Prefs {
		p := ipn.NewPrefs()
		p.ControlURL = ipn.DefaultControlURL
		p.RunSSH = true
		p.Persist = &persist.Persist{
			UserProfile: tailcfg.UserProfile{LoginName: "user@example.com"},
		}
		return p
	}

	t.Run("bare-up", func(t *testing.T) {
		curPrefs := newCurPrefs()
		prefs := ipn.NewPrefs()
		prefs.ControlURL = curPrefs.ControlURL

		env := upCheckEnv{
			goos:         runtime.GOOS,
			flagSet:      flag.NewFlagSet("up", flag.ContinueOnError),
			backendState: ipn.Running.String(),
		}
		simpleUp, _, err := updatePrefs(prefs, curPrefs, env)
		if err != nil {
			t.Fatalf("bare up over Tailscale SSH: unexpected error: %v", err)
		}
		if !simpleUp {
			t.Errorf("bare up: simpleUp = false, want true")
		}
	})

	t.Run("ssh-toggle-off", func(t *testing.T) {
		curPrefs := newCurPrefs()
		prefsCopy := *curPrefs
		prefs := &prefsCopy
		prefs.RunSSH = false

		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		fs.Bool("ssh", false, "")
		fs.Set("ssh", "false")
		env := upCheckEnv{
			goos:         runtime.GOOS,
			flagSet:      fs,
			backendState: ipn.Running.String(),
		}
		if _, _, err := updatePrefs(prefs, curPrefs, env); err == nil {
			t.Fatalf("--ssh=false over Tailscale SSH: expected lose-ssh risk error, got nil")
		}
	})
}
