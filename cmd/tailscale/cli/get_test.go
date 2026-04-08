// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/preftype"
)

func TestPrefValue(t *testing.T) {
	port := uint16(41641)
	peerKey := key.NewNode().Public()
	exitPeerID := tailcfg.StableNodeID("exit-peer")
	exitPeerIP := netip.MustParseAddr("100.64.0.5")

	stWithExitPeer := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey: {
				ID:           exitPeerID,
				TailscaleIPs: []netip.Addr{exitPeerIP},
			},
		},
	}

	tests := []struct {
		name  string
		flag  string
		prefs *ipn.Prefs
		st    *ipnstate.Status
		want  any
	}{
		// Simple boolean prefs.
		{
			name:  "accept-routes-true",
			flag:  "accept-routes",
			prefs: &ipn.Prefs{RouteAll: true},
			want:  true,
		},
		{
			name:  "accept-routes-false",
			flag:  "accept-routes",
			prefs: &ipn.Prefs{},
			want:  false,
		},
		{
			name:  "accept-dns",
			flag:  "accept-dns",
			prefs: &ipn.Prefs{CorpDNS: true},
			want:  true,
		},
		{
			name:  "exit-node-allow-lan-access",
			flag:  "exit-node-allow-lan-access",
			prefs: &ipn.Prefs{ExitNodeAllowLANAccess: true},
			want:  true,
		},
		{
			name:  "shields-up",
			flag:  "shields-up",
			prefs: &ipn.Prefs{ShieldsUp: true},
			want:  true,
		},
		{
			name:  "ssh",
			flag:  "ssh",
			prefs: &ipn.Prefs{RunSSH: true},
			want:  true,
		},
		{
			name:  "advertise-connector",
			flag:  "advertise-connector",
			prefs: &ipn.Prefs{AppConnector: ipn.AppConnectorPrefs{Advertise: true}},
			want:  true,
		},
		{
			name:  "update-check",
			flag:  "update-check",
			prefs: &ipn.Prefs{AutoUpdate: ipn.AutoUpdatePrefs{Check: true}},
			want:  true,
		},
		{
			name:  "report-posture",
			flag:  "report-posture",
			prefs: &ipn.Prefs{PostureChecking: true},
			want:  true,
		},
		{
			name:  "webclient",
			flag:  "webclient",
			prefs: &ipn.Prefs{RunWebClient: true},
			want:  true,
		},
		{
			name:  "unattended",
			flag:  "unattended",
			prefs: &ipn.Prefs{ForceDaemon: true},
			want:  true,
		},

		// Simple string prefs.
		{
			name:  "hostname",
			flag:  "hostname",
			prefs: &ipn.Prefs{Hostname: "myhost"},
			want:  "myhost",
		},
		{
			name:  "nickname",
			flag:  "nickname",
			prefs: &ipn.Prefs{ProfileName: "work"},
			want:  "work",
		},
		{
			name:  "operator",
			flag:  "operator",
			prefs: &ipn.Prefs{OperatorUser: "alice"},
			want:  "alice",
		},

		// exit-node has three branches.
		{
			name:  "exit-node/auto",
			flag:  "exit-node",
			prefs: &ipn.Prefs{AutoExitNode: ipn.AnyExitNode},
			want:  "auto:any",
		},
		{
			name:  "exit-node/by-ip",
			flag:  "exit-node",
			prefs: &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("100.64.0.1")},
			want:  "100.64.0.1",
		},
		{
			name:  "exit-node/by-id-resolves-via-status",
			flag:  "exit-node",
			prefs: &ipn.Prefs{ExitNodeID: exitPeerID},
			st:    stWithExitPeer,
			want:  exitPeerIP.String(),
		},
		{
			name:  "exit-node/empty",
			flag:  "exit-node",
			prefs: &ipn.Prefs{},
			want:  "",
		},

		// advertise-routes filters out exit routes, comma-joins.
		{
			name: "advertise-routes/multiple",
			flag: "advertise-routes",
			prefs: &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/16"),
			}},
			want: "10.0.0.0/24,192.168.0.0/16",
		},
		{
			name: "advertise-routes/excludes-exit-routes",
			flag: "advertise-routes",
			prefs: &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			}},
			want: "10.0.0.0/24",
		},
		{
			name:  "advertise-routes/empty",
			flag:  "advertise-routes",
			prefs: &ipn.Prefs{},
			want:  "",
		},

		// advertise-exit-node derives from AdvertiseRoutes.
		{
			name: "advertise-exit-node/true",
			flag: "advertise-exit-node",
			prefs: &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			}},
			want: true,
		},
		{
			name:  "advertise-exit-node/false-empty",
			flag:  "advertise-exit-node",
			prefs: &ipn.Prefs{},
			want:  false,
		},
		{
			name: "advertise-exit-node/false-only-subnet",
			flag: "advertise-exit-node",
			prefs: &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			}},
			want: false,
		},

		// auto-update and sync use opt.Bool.EqualBool(true).
		{
			name:  "auto-update/unset-is-false",
			flag:  "auto-update",
			prefs: &ipn.Prefs{},
			want:  false,
		},
		{
			name:  "auto-update/explicit-true",
			flag:  "auto-update",
			prefs: &ipn.Prefs{AutoUpdate: ipn.AutoUpdatePrefs{Apply: opt.NewBool(true)}},
			want:  true,
		},
		{
			name:  "auto-update/explicit-false",
			flag:  "auto-update",
			prefs: &ipn.Prefs{AutoUpdate: ipn.AutoUpdatePrefs{Apply: opt.NewBool(false)}},
			want:  false,
		},
		{
			name:  "sync/unset-is-false",
			flag:  "sync",
			prefs: &ipn.Prefs{},
			want:  false,
		},
		{
			name:  "sync/explicit-true",
			flag:  "sync",
			prefs: &ipn.Prefs{Sync: opt.NewBool(true)},
			want:  true,
		},

		// snat-subnet-routes is inverted.
		{
			name:  "snat-subnet-routes/default-true",
			flag:  "snat-subnet-routes",
			prefs: &ipn.Prefs{},
			want:  true,
		},
		{
			name:  "snat-subnet-routes/false-when-no-snat",
			flag:  "snat-subnet-routes",
			prefs: &ipn.Prefs{NoSNAT: true},
			want:  false,
		},

		// stateful-filtering: the inversion of NoStatefulFiltering, defaulting on.
		{
			name:  "stateful-filtering/unset-is-true",
			flag:  "stateful-filtering",
			prefs: &ipn.Prefs{},
			want:  true,
		},
		{
			name:  "stateful-filtering/explicit-disabled-no-stateful",
			flag:  "stateful-filtering",
			prefs: &ipn.Prefs{NoStatefulFiltering: opt.NewBool(true)},
			want:  false,
		},
		{
			name:  "stateful-filtering/explicit-enabled-no-stateful",
			flag:  "stateful-filtering",
			prefs: &ipn.Prefs{NoStatefulFiltering: opt.NewBool(false)},
			want:  true,
		},

		// netfilter-mode renders via String().
		{
			name:  "netfilter-mode/off",
			flag:  "netfilter-mode",
			prefs: &ipn.Prefs{NetfilterMode: preftype.NetfilterOff},
			want:  "off",
		},
		{
			name:  "netfilter-mode/on",
			flag:  "netfilter-mode",
			prefs: &ipn.Prefs{NetfilterMode: preftype.NetfilterOn},
			want:  "on",
		},

		// relay-server-port: nil pointer vs explicit.
		{
			name:  "relay-server-port/unset",
			flag:  "relay-server-port",
			prefs: &ipn.Prefs{},
			want:  "",
		},
		{
			name:  "relay-server-port/set",
			flag:  "relay-server-port",
			prefs: &ipn.Prefs{RelayServerPort: &port},
			want:  "41641",
		},

		// relay-server-static-endpoints: empty vs joined.
		{
			name:  "relay-server-static-endpoints/empty",
			flag:  "relay-server-static-endpoints",
			prefs: &ipn.Prefs{},
			want:  "",
		},
		{
			name: "relay-server-static-endpoints/multiple",
			flag: "relay-server-static-endpoints",
			prefs: &ipn.Prefs{RelayServerStaticEndpoints: []netip.AddrPort{
				netip.MustParseAddrPort("192.0.2.1:40000"),
				netip.MustParseAddrPort("[2001:db8::1]:40000"),
			}},
			want: "192.0.2.1:40000,[2001:db8::1]:40000",
		},

		// Unknown flag returns nil. This guards against the default branch
		// silently producing nil for a flag that should have been wired up.
		{
			name:  "unknown-flag",
			flag:  "no-such-flag",
			prefs: &ipn.Prefs{},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := tt.st
			if st == nil {
				st = &ipnstate.Status{}
			}
			got := prefValue(tt.flag, tt.prefs, st)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("prefValue(%q) = %v (%T), want %v (%T)",
					tt.flag, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestPrefValueCoversAllSetFlags is the load-bearing guard: every flag
// that "tailscale set" exposes must have a corresponding prefValue case,
// or "tailscale get" silently returns nil for it. It iterates the set
// command's flag set across the platforms whose flag sets differ, so
// OS-conditional flags (snat-subnet-routes, netfilter-mode, unattended,
// operator, ...) are all covered.
func TestPrefValueCoversAllSetFlags(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			var dummy setArgsT
			fs := newSetFlagSet(goos, &dummy)
			fs.VisitAll(func(f *flag.Flag) {
				if preflessFlag(f.Name) {
					return
				}
				if got := prefValue(f.Name, &ipn.Prefs{}, &ipnstate.Status{}); got == nil {
					t.Errorf("prefValue(%q) returned nil; add a case for it in prefValue", f.Name)
				}
			})
		})
	}
}

func TestGetSettingsFromPrefsHiddenFlag(t *testing.T) {
	prefs := &ipn.Prefs{}
	st := &ipnstate.Status{}

	visible := getSettingsFromPrefs(prefs, st, "linux", false)
	if containsSetting(visible, "sync") {
		t.Error("expected hidden flag --sync to be excluded when includeHidden=false")
	}
	if !containsSetting(visible, "accept-dns") {
		t.Error("expected visible flag --accept-dns to be included")
	}

	withHidden := getSettingsFromPrefs(prefs, st, "linux", true)
	if !containsSetting(withHidden, "sync") {
		t.Error("expected hidden flag --sync to be included when includeHidden=true")
	}

	// Ordering must match the set flag set's VisitAll order.
	var wantOrder []string
	var dummy setArgsT
	newSetFlagSet("linux", &dummy).VisitAll(func(f *flag.Flag) {
		if preflessFlag(f.Name) {
			return
		}
		wantOrder = append(wantOrder, f.Name)
	})
	var gotOrder []string
	for _, s := range withHidden {
		gotOrder = append(gotOrder, s.name)
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Errorf("setting order = %v, want %v", gotOrder, wantOrder)
	}
}

func TestSelectSettings(t *testing.T) {
	prefs := &ipn.Prefs{Hostname: "h", CorpDNS: true}
	st := &ipnstate.Status{}
	const goos = "linux"

	t.Run("empty-args-returns-all-visible", func(t *testing.T) {
		got, wantAll, err := selectSettings(prefs, st, goos, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !wantAll {
			t.Error("wantAll = false; want true")
		}
		if containsSetting(got, "sync") {
			t.Error("hidden flag --sync leaked into all-settings result")
		}
		if !containsSetting(got, "hostname") {
			t.Error("missing --hostname in all-settings result")
		}
	})

	t.Run("all-arg-same-as-empty", func(t *testing.T) {
		empty, _, err := selectSettings(prefs, st, goos, nil)
		if err != nil {
			t.Fatal(err)
		}
		allArg, wantAll, err := selectSettings(prefs, st, goos, []string{"all"})
		if err != nil {
			t.Fatal(err)
		}
		if !wantAll {
			t.Error("wantAll = false; want true for explicit \"all\"")
		}
		if !reflect.DeepEqual(empty, allArg) {
			t.Errorf("\"all\" produced %v, empty produced %v", allArg, empty)
		}
	})

	t.Run("specific-visible-flag", func(t *testing.T) {
		got, wantAll, err := selectSettings(prefs, st, goos, []string{"hostname"})
		if err != nil {
			t.Fatal(err)
		}
		if wantAll {
			t.Error("wantAll = true; want false for specific name")
		}
		if len(got) != 1 || got[0].name != "hostname" || got[0].value != "h" {
			t.Errorf("got %+v, want [{hostname h}]", got)
		}
	})

	t.Run("specific-hidden-flag", func(t *testing.T) {
		// Hidden flags must be reachable by exact name.
		got, _, err := selectSettings(prefs, st, goos, []string{"sync"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].name != "sync" {
			t.Errorf("got %+v, want [{sync ...}]", got)
		}
	})

	t.Run("unknown-flag-errors", func(t *testing.T) {
		_, _, err := selectSettings(prefs, st, goos, []string{"no-such-flag"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unknown setting") || !strings.Contains(err.Error(), "no-such-flag") {
			t.Errorf("error %q missing expected substrings", err)
		}
	})

	t.Run("too-many-args-errors", func(t *testing.T) {
		_, _, err := selectSettings(prefs, st, goos, []string{"hostname", "ssh"})
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "too many arguments") {
			t.Errorf("error %q missing \"too many arguments\"", err)
		}
	})

	t.Run("os-conditional-flag-on-wrong-goos", func(t *testing.T) {
		// "netfilter-mode" is registered only on linux. Asking for it
		// on darwin should produce an "unknown setting" error.
		_, _, err := selectSettings(prefs, st, "darwin", []string{"netfilter-mode"})
		if err == nil || !strings.Contains(err.Error(), "unknown setting") {
			t.Errorf("got err=%v, want \"unknown setting\"", err)
		}
		// And operator is peer-creds-only.
		if safesocket.GOOSUsesPeerCreds("windows") {
			t.Skip("operator is exposed on windows")
		}
		_, _, err = selectSettings(prefs, st, "windows", []string{"operator"})
		if err == nil || !strings.Contains(err.Error(), "unknown setting") {
			t.Errorf("got err=%v, want \"unknown setting\"", err)
		}
	})
}

func TestGetOutputJSON(t *testing.T) {
	var buf bytes.Buffer
	tstest.Replace[io.Writer](t, &Stdout, &buf)

	settings := []getSetting{
		{name: "accept-dns", value: true},
		{name: "hostname", value: "myhost"},
		{name: "advertise-routes", value: "10.0.0.0/24"},
		{name: "shields-up", value: false},
	}
	if err := getOutputJSON(settings); err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	want := map[string]any{
		"accept-dns":       true,
		"hostname":         "myhost",
		"advertise-routes": "10.0.0.0/24",
		"shields-up":       false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGetOutputTable(t *testing.T) {
	var buf bytes.Buffer
	tstest.Replace[io.Writer](t, &Stdout, &buf)

	settings := []getSetting{
		{name: "accept-dns", value: true},
		{name: "hostname", value: "myhost"},
	}
	if err := getOutputTable(settings); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "VALUE") {
		t.Errorf("header line = %q, want NAME ... VALUE", lines[0])
	}
	if !strings.HasPrefix(lines[1], "accept-dns") || !strings.HasSuffix(lines[1], "true") {
		t.Errorf("row 1 = %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "hostname") || !strings.HasSuffix(lines[2], "myhost") {
		t.Errorf("row 2 = %q", lines[2])
	}
}

func TestGetOutputSetFlags(t *testing.T) {
	var buf bytes.Buffer
	tstest.Replace[io.Writer](t, &Stdout, &buf)

	settings := []getSetting{
		{name: "ssh", value: true},
		{name: "shields-up", value: false},
		{name: "hostname", value: "myhost"},
		{name: "advertise-routes", value: ""},
	}
	if err := getOutputSetFlags(settings); err != nil {
		t.Fatal(err)
	}

	got := strings.TrimSpace(buf.String())
	// true → bare flag; false → --flag=false; empty string → --flag=; other → --flag=value
	want := "--ssh --shields-up=false --hostname=myhost --advertise-routes="
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// containsSetting reports whether settings contains a setting with the given name.
func containsSetting(settings []getSetting, name string) bool {
	for _, s := range settings {
		if s.name == name {
			return true
		}
	}
	return false
}
