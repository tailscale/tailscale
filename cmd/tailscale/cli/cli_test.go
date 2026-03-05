// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	stdcmp "cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/health/healthmsg"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/tstest"
	"tailscale.com/tstest/deptest"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/util/set"
	"tailscale.com/version/distro"
)

func TestPanicIfAnyEnvCheckedInInit(t *testing.T) {
	envknob.PanicIfAnyEnvCheckedInInit()
}

func TestShortUsage(t *testing.T) {
	t.Setenv("TAILSCALE_USE_WIP_CODE", "1")
	if !envknob.UseWIPCode() {
		t.Fatal("expected envknob.UseWIPCode() to be true")
	}

	walkCommands(newRootCmd(), func(w cmdWalk) bool {
		c, parents := w.Command, w.parents

		// Words that we expect to be in the usage.
		words := make([]string, len(parents)+1)
		for i, parent := range parents {
			words[i] = parent.Name
		}
		words[len(parents)] = c.Name

		// Check the ShortHelp starts with a capital letter.
		if prefix, help := trimPrefixes(c.ShortHelp, "HIDDEN: ", "[ALPHA] ", "[BETA] "); help != "" {
			if 'a' <= help[0] && help[0] <= 'z' {
				if len(help) > 20 {
					help = help[:20] + "…"
				}
				caphelp := string(help[0]-'a'+'A') + help[1:]
				t.Errorf("command: %s: ShortHelp %q should start with a capital letter %q", strings.Join(words, " "), prefix+help, prefix+caphelp)
			}
		}

		// Check all words appear in the usage.
		usage := c.ShortUsage
		for _, word := range words {
			var ok bool
			usage, ok = cutWord(usage, word)
			if !ok {
				full := strings.Join(words, " ")
				t.Errorf("command: %s: usage %q should contain the full path %q", full, c.ShortUsage, full)
				return true
			}
		}
		return true
	})
}

func trimPrefixes(full string, prefixes ...string) (trimmed, remaining string) {
	s := full
start:
	for _, p := range prefixes {
		var ok bool
		s, ok = strings.CutPrefix(s, p)
		if ok {
			goto start
		}
	}
	return full[:len(full)-len(s)], s
}

// cutWord("tailscale debug scale 123", "scale") returns (" 123", true).
func cutWord(s, w string) (after string, ok bool) {
	var p string
	for {
		p, s, ok = strings.Cut(s, w)
		if !ok {
			return "", false
		}
		if p != "" && isWordChar(p[len(p)-1]) {
			continue
		}
		if s != "" && isWordChar(s[0]) {
			continue
		}
		return s, true
	}
}

func isWordChar(r byte) bool {
	return r == '_' ||
		('0' <= r && r <= '9') ||
		('A' <= r && r <= 'Z') ||
		('a' <= r && r <= 'z')
}

func TestCutWord(t *testing.T) {
	tests := []struct {
		in   string
		word string
		out  string
		ok   bool
	}{
		{"tailscale debug", "debug", "", true},
		{"tailscale debug", "bug", "", false},
		{"tailscale debug", "tail", "", false},
		{"tailscale debug scaley scale 123", "scale", " 123", true},
	}
	for _, test := range tests {
		out, ok := cutWord(test.in, test.word)
		if out != test.out || ok != test.ok {
			t.Errorf("cutWord(%q, %q) = (%q, %t), wanted (%q, %t)", test.in, test.word, out, ok, test.out, test.ok)
		}
	}
}

// geese is a collection of gooses. It need not be complete.
// But it should include anything handled specially (e.g. linux, windows)
// and at least one thing that's not (darwin, freebsd).
var geese = []string{"linux", "darwin", "windows", "freebsd"}

// Test that checkForAccidentalSettingReverts's updateMaskedPrefsFromUpFlag can handle
// all flags. This will panic if a new flag creeps in that's unhandled.
//
// Also, issue 1880: advertise-exit-node was being ignored. Verify that all flags cause an edit.
func TestUpdateMaskedPrefsFromUpFlag(t *testing.T) {
	for _, goos := range geese {
		var upArgs upArgsT
		fs := newUpFlagSet(goos, &upArgs, "up")
		fs.VisitAll(func(f *flag.Flag) {
			mp := new(ipn.MaskedPrefs)
			updateMaskedPrefsFromUpOrSetFlag(mp, f.Name)
			got := mp.Pretty()
			wantEmpty := preflessFlag(f.Name)
			isEmpty := got == "MaskedPrefs{}"
			if isEmpty != wantEmpty {
				t.Errorf("flag %q created MaskedPrefs %s; want empty=%v", f.Name, got, wantEmpty)
			}
		})
	}
}

func TestCheckForAccidentalSettingReverts(t *testing.T) {
	tests := []struct {
		name     string
		flags    []string // argv to be parsed by FlagSet
		curPrefs *ipn.Prefs

		curExitNodeIP netip.Addr
		curUser       string // os.Getenv("USER") on the client side
		goos          string // empty means "linux"
		distro        distro.Distro
		backendState  string // empty means "Running"

		want string
	}{
		{
			name:  "bare_up_means_up",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         false,
				Hostname:            "foo",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:         "bare_up_needs_login_default_prefs",
			flags:        []string{},
			curPrefs:     ipn.NewPrefs(),
			backendState: ipn.NeedsLogin.String(),
			want:         "",
		},
		{
			name:  "bare_up_needs_login_losing_prefs",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				// defaults:
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         false,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
				// non-default:
				CorpDNS: false,
			},
			backendState: ipn.NeedsLogin.String(),
			want:         accidentalUpPrefix + " --accept-dns=false",
		},
		{
			name:  "losing_hostname",
			flags: []string{"--accept-dns"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         false,
				Hostname:            "foo",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --accept-dns --hostname=foo",
		},
		{
			name:  "hostname_changing_explicitly",
			flags: []string{"--hostname=bar"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				Hostname:            "foo",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:  "hostname_changing_empty_explicitly",
			flags: []string{"--hostname="},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				Hostname:            "foo",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			// Issue 1725: "tailscale up --authkey=..." (or other non-empty flags) works from
			// a fresh server's initial prefs.
			name:     "up_with_default_prefs",
			flags:    []string{"--authkey=foosdlkfjskdljf"},
			curPrefs: ipn.NewPrefs(),
			want:     "",
		},
		{
			name:  "implicit_operator_change",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				OperatorUser:        "alice",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --hostname=foo --operator=alice",
		},
		{
			name:  "implicit_operator_matches_shell_user",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				OperatorUser:        "alice",
				NoStatefulFiltering: opt.NewBool(true),
			},
			curUser: "alice",
			want:    "",
		},
		{
			name:  "error_advertised_routes_exit_node_removed",
			flags: []string{"--advertise-routes=10.0.42.0/24"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.0.42.0/24"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --advertise-routes=10.0.42.0/24 --advertise-exit-node",
		},
		{
			name:  "advertised_routes_exit_node_removed_explicit",
			flags: []string{"--advertise-routes=10.0.42.0/24", "--advertise-exit-node=false"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.0.42.0/24"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:  "advertised_routes_includes_the_0_routes", // but no --advertise-exit-node
			flags: []string{"--advertise-routes=11.1.43.0/24,0.0.0.0/0,::/0"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.0.42.0/24"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:  "advertise_exit_node", // Issue 1859
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:  "advertise_exit_node_over_existing_routes",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("1.2.0.0/16"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "advertise_exit_node_over_existing_routes_and_exit_node",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
					netip.MustParsePrefix("1.2.0.0/16"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "exit_node_clearing", // Issue 1777
			flags: []string{"--exit-node="},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				ExitNodeID:          "fooID",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "",
		},
		{
			name:  "remove_all_implicit",
			flags: []string{"--force-reauth"},
			curPrefs: &ipn.Prefs{
				WantRunning:   true,
				ControlURL:    ipn.DefaultControlURL,
				RouteAll:      true,
				ExitNodeIP:    netip.MustParseAddr("100.64.5.6"),
				CorpDNS:       false,
				ShieldsUp:     true,
				AdvertiseTags: []string{"tag:foo", "tag:bar"},
				Hostname:      "myhostname",
				ForceDaemon:   true,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/16"),
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				NetfilterMode:       preftype.NetfilterNoDivert,
				OperatorUser:        "alice",
				NoStatefulFiltering: opt.NewBool(true),
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --force-reauth --accept-dns=false --accept-routes --advertise-exit-node --advertise-routes=10.0.0.0/16 --advertise-tags=tag:foo,tag:bar --exit-node=100.64.5.6 --hostname=myhostname --netfilter-mode=nodivert --operator=alice --shields-up",
		},
		{
			name:  "remove_all_implicit_except_hostname",
			flags: []string{"--hostname=newhostname"},
			curPrefs: &ipn.Prefs{
				WantRunning:   true,
				ControlURL:    ipn.DefaultControlURL,
				RouteAll:      true,
				ExitNodeIP:    netip.MustParseAddr("100.64.5.6"),
				CorpDNS:       false,
				ShieldsUp:     true,
				AdvertiseTags: []string{"tag:foo", "tag:bar"},
				Hostname:      "myhostname",
				ForceDaemon:   true,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/16"),
				},
				NetfilterMode:       preftype.NetfilterNoDivert,
				OperatorUser:        "alice",
				NoStatefulFiltering: opt.NewBool(true),
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --hostname=newhostname --accept-dns=false --accept-routes --advertise-routes=10.0.0.0/16 --advertise-tags=tag:foo,tag:bar --exit-node=100.64.5.6 --netfilter-mode=nodivert --operator=alice --shields-up",
		},
		{
			name:  "loggedout_is_implicit",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				LoggedOut:           true,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "", // not an error. LoggedOut is implicit.
		},
		{
			// Test that a pre-1.8 version of Tailscale with bogus NoSNAT pref
			// values is able to enable exit nodes without warnings.
			name:  "make_windows_exit_node",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				CorpDNS:    true,
				RouteAll:   true,

				// And assume this no-op accidental pre-1.8 value:
				NoSNAT: true,
			},
			goos: "windows",
			want: "", // not an error
		},
		{
			name:  "ignore_netfilter_change_non_linux",
			flags: []string{"--accept-dns"},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,

				NetfilterMode: preftype.NetfilterNoDivert, // we never had this bug, but pretend it got set non-zero on Windows somehow
			},
			goos: "openbsd",
			want: "", // not an error
		},
		{
			name:  "operator_losing_routes_step1", // https://twitter.com/EXPbits/status/1390418145047887877
			flags: []string{"--operator=expbits"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
					netip.MustParsePrefix("1.2.0.0/16"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --operator=expbits --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "operator_losing_routes_step2", // https://twitter.com/EXPbits/status/1390418145047887877
			flags: []string{"--operator=expbits", "--advertise-routes=1.2.0.0/16"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
					netip.MustParsePrefix("1.2.0.0/16"),
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --advertise-routes=1.2.0.0/16 --operator=expbits --advertise-exit-node",
		},
		{
			name:  "errors_preserve_explicit_flags",
			flags: []string{"--reset", "--force-reauth=false", "--authkey=secretrand"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				WantRunning:   false,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				Hostname:            "foo",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --auth-key=secretrand --force-reauth=false --reset --hostname=foo",
		},
		{
			name:  "error_exit_node_omit_with_ip_pref",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				ExitNodeIP:          netip.MustParseAddr("100.64.5.4"),
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --hostname=foo --exit-node=100.64.5.4",
		},
		{
			name:          "error_exit_node_omit_with_id_pref",
			flags:         []string{"--hostname=foo"},
			curExitNodeIP: netip.MustParseAddr("100.64.5.7"),
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				ExitNodeID:          "some_stable_id",
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --hostname=foo --exit-node=100.64.5.7",
		},
		{
			name:          "error_exit_node_and_allow_lan_omit_with_id_pref", // Issue 3480
			flags:         []string{"--hostname=foo"},
			curExitNodeIP: netip.MustParseAddr("100.2.3.4"),
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,

				ExitNodeAllowLANAccess: true,
				ExitNodeID:             "some_stable_id",
				NoStatefulFiltering:    opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --hostname=foo --exit-node-allow-lan-access --exit-node=100.2.3.4",
		},
		{
			name:  "ignore_login_server_synonym",
			flags: []string{"--login-server=https://controlplane.tailscale.com"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: "", // not an error
		},
		{
			name:  "ignore_login_server_synonym_on_other_change",
			flags: []string{"--netfilter-mode=off"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             false,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --netfilter-mode=off --accept-dns=false",
		},
		{
			// Issue 3176: on Synology, don't require --accept-routes=false because user
			// might've had an old install, and we don't support --accept-routes anyway.
			name:  "synology_permit_omit_accept_routes",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				RouteAll:            true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			goos:   "linux",
			distro: distro.Synology,
			want:   "",
		},
		{
			// Same test case as "synology_permit_omit_accept_routes" above, but
			// on non-Synology distro.
			name:  "not_synology_dont_permit_omit_accept_routes",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				RouteAll:            true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			goos:   "linux",
			distro: "", // not Synology
			want:   accidentalUpPrefix + " --hostname=foo --accept-routes",
		},
		{
			name:  "profile_name_ignored_in_up",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				ProfileName:         "foo",
				NoStatefulFiltering: opt.NewBool(true),
			},
			goos: "linux",
			want: "",
		},
		{
			name:  "losing_report_posture",
			flags: []string{"--accept-dns"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         false,
				CorpDNS:             true,
				PostureChecking:     true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			want: accidentalUpPrefix + " --accept-dns --report-posture",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goos := stdcmp.Or(tt.goos, "linux")
			backendState := stdcmp.Or(tt.backendState, ipn.Running.String())
			// Needs to match the other conditions in checkForAccidentalSettingReverts
			tt.curPrefs.Persist = &persist.Persist{
				UserProfile: tailcfg.UserProfile{
					LoginName: "janet",
				},
			}
			var upArgs upArgsT
			flagSet := newUpFlagSet(goos, &upArgs, "up")
			flags := CleanUpArgs(tt.flags)
			flagSet.Parse(flags)
			newPrefs, err := prefsFromUpArgs(upArgs, t.Logf, new(ipnstate.Status), goos)
			if err != nil {
				t.Fatal(err)
			}
			upEnv := upCheckEnv{
				goos:          goos,
				flagSet:       flagSet,
				curExitNodeIP: tt.curExitNodeIP,
				distro:        tt.distro,
				user:          tt.curUser,
				backendState:  backendState,
			}
			applyImplicitPrefs(newPrefs, tt.curPrefs, upEnv)
			var got string
			if _, err := checkForAccidentalSettingReverts(newPrefs, tt.curPrefs, upEnv); err != nil {
				got = err.Error()
			}
			if strings.TrimSpace(got) != tt.want {
				t.Errorf("unexpected result\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}

func upArgsFromOSArgs(goos string, flagArgs ...string) (args upArgsT) {
	fs := newUpFlagSet(goos, &args, "up")
	fs.Parse(flagArgs) // populates args
	return
}

func TestPrefsFromUpArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     upArgsT
		goos     string           // runtime.GOOS; empty means linux
		st       *ipnstate.Status // or nil
		want     *ipn.Prefs
		wantErr  string
		wantWarn string
	}{
		{
			name: "default_linux",
			goos: "linux",
			args: upArgsFromOSArgs("linux"),
			want: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         true,
				NoSNAT:              false,
				NoStatefulFiltering: "true",
				NetfilterMode:       preftype.NetfilterOn,
				CorpDNS:             true,
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "default_windows",
			goos: "windows",
			args: upArgsFromOSArgs("windows"),
			want: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				WantRunning:         true,
				CorpDNS:             true,
				RouteAll:            true,
				NoSNAT:              false,
				NoStatefulFiltering: "true",
				NetfilterMode:       preftype.NetfilterOn,
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "advertise_default_route",
			args: upArgsFromOSArgs("linux", "--advertise-exit-node"),
			want: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: true,
				CorpDNS:     true,
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				NoStatefulFiltering: "true",
				NetfilterMode:       preftype.NetfilterOn,
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "error_advertise_route_invalid_ip",
			args: upArgsT{
				advertiseRoutes: "foo",
			},
			wantErr: `"foo" is not a valid IP address or CIDR prefix`,
		},
		{
			name: "error_advertise_route_unmasked_bits",
			args: upArgsT{
				advertiseRoutes: "1.2.3.4/16",
			},
			wantErr: `1.2.3.4/16 has non-address bits set; expected 1.2.0.0/16`,
		},
		{
			name: "error_exit_node_bad_ip",
			args: upArgsT{
				exitNodeIP: "foo",
			},
			wantErr: `invalid value "foo" for --exit-node; must be IP or unique node name`,
		},
		{
			name: "error_exit_node_allow_lan_without_exit_node",
			args: upArgsT{
				exitNodeAllowLANAccess: true,
			},
			wantErr: `--exit-node-allow-lan-access can only be used with --exit-node`,
		},
		{
			name: "error_tag_prefix",
			args: upArgsT{
				advertiseTags: "foo",
			},
			wantErr: `tag: "foo": tags must start with 'tag:'`,
		},
		{
			name: "error_long_hostname",
			args: upArgsT{
				hostname: strings.Repeat(strings.Repeat("a", 63)+".", 4),
			},
			wantErr: `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" is too long to be a DNS name`,
		},
		{
			name: "error_long_label",
			args: upArgsT{
				hostname: strings.Repeat("a", 64) + ".example.com",
			},
			wantErr: `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" is not a valid DNS label`,
		},
		{
			name: "error_linux_netfilter_empty",
			args: upArgsT{
				netfilterMode: "",
			},
			wantErr: `invalid value --netfilter-mode=""`,
		},
		{
			name: "error_linux_netfilter_bogus",
			args: upArgsT{
				netfilterMode: "bogus",
			},
			wantErr: `invalid value --netfilter-mode="bogus"`,
		},
		{
			name: "error_exit_node_ip_is_self_ip",
			args: upArgsT{
				exitNodeIP: "100.105.106.107",
			},
			st: &ipnstate.Status{
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.105.106.107")},
			},
			wantErr: `cannot use 100.105.106.107 as an exit node as it is a local IP address to this machine; did you mean --advertise-exit-node?`,
		},
		{
			name: "warn_linux_netfilter_nodivert",
			goos: "linux",
			args: upArgsT{
				netfilterMode: "nodivert",
			},
			wantWarn: "netfilter=nodivert; add iptables calls to ts-* chains manually.",
			want: &ipn.Prefs{
				WantRunning:         true,
				NetfilterMode:       preftype.NetfilterNoDivert,
				NoSNAT:              true,
				NoStatefulFiltering: "true",
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "warn_linux_netfilter_off",
			goos: "linux",
			args: upArgsT{
				netfilterMode: "off",
			},
			wantWarn: "netfilter=off; configure iptables yourself.",
			want: &ipn.Prefs{
				WantRunning:         true,
				NetfilterMode:       preftype.NetfilterOff,
				NoSNAT:              true,
				NoStatefulFiltering: "true",
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "via_route_good",
			goos: "linux",
			args: upArgsT{
				advertiseRoutes: "fd7a:115c:a1e0:b1a::bb:10.0.0.0/112",
				netfilterMode:   "off",
			},
			want: &ipn.Prefs{
				WantRunning:         true,
				NoSNAT:              true,
				NoStatefulFiltering: "true",
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a::bb:10.0.0.0/112"),
				},
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "via_route_good_16_bit",
			goos: "linux",
			args: upArgsT{
				advertiseRoutes: "fd7a:115c:a1e0:b1a::aabb:10.0.0.0/112",
				netfilterMode:   "off",
			},
			want: &ipn.Prefs{
				WantRunning:         true,
				NoSNAT:              true,
				NoStatefulFiltering: "true",
				AdvertiseRoutes: []netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a::aabb:10.0.0.0/112"),
				},
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
				},
			},
		},
		{
			name: "via_route_short_prefix",
			goos: "linux",
			args: upArgsT{
				advertiseRoutes: "fd7a:115c:a1e0:b1a::/64",
				netfilterMode:   "off",
			},
			wantErr: "fd7a:115c:a1e0:b1a::/64 4-in-6 prefix must be at least a /96",
		},
		{
			name: "via_route_short_reserved_siteid",
			goos: "linux",
			args: upArgsT{
				advertiseRoutes: "fd7a:115c:a1e0:b1a:1234:5678::/112",
				netfilterMode:   "off",
			},
			wantErr: "route fd7a:115c:a1e0:b1a:1234:5678::/112 contains invalid site ID 12345678; must be 0xffff or less",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnBuf tstest.MemLogger
			goos := stdcmp.Or(tt.goos, "linux")
			st := tt.st
			if st == nil {
				st = new(ipnstate.Status)
			}
			got, err := prefsFromUpArgs(tt.args, warnBuf.Logf, st, goos)
			gotErr := fmt.Sprint(err)
			if tt.wantErr != "" {
				if tt.wantErr != gotErr {
					t.Errorf("wrong error.\n got error: %v\nwant error: %v\n", gotErr, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == nil {
				t.Fatal("tt.want is nil")
			}
			if !got.Equals(tt.want) {
				jgot, _ := json.MarshalIndent(got, "", "\t")
				jwant, _ := json.MarshalIndent(tt.want, "", "\t")
				if bytes.Equal(jgot, jwant) {
					t.Logf("prefs differ only in non-JSON-visible ways (nil/non-nil zero-length arrays)")
				}
				t.Errorf("wrong prefs\n got: %s\nwant: %s\n\ngot: %s\nwant: %s\n",
					got.Pretty(), tt.want.Pretty(),
					jgot, jwant,
				)

			}
		})
	}

}

func TestPrefFlagMapping(t *testing.T) {
	prefHasFlag := map[string]bool{}
	for _, pv := range prefsOfFlag {
		for _, pref := range pv {
			prefHasFlag[strings.Split(pref, ".")[0]] = true
		}
	}

	prefType := reflect.TypeFor[ipn.Prefs]()
	for i := range prefType.NumField() {
		prefName := prefType.Field(i).Name
		if prefHasFlag[prefName] {
			continue
		}
		switch prefName {
		case "AllowSingleHosts":
			// Fake pref for downgrade compat. See #12058.
			continue
		case "WantRunning", "Persist", "LoggedOut":
			// All explicitly handled (ignored) by checkForAccidentalSettingReverts.
			continue
		case "OSVersion", "DeviceModel":
			// Only used by Android, which doesn't have a CLI mode anyway, so
			// fine to not map.
			continue
		case "NotepadURLs":
			// TODO(bradfitz): https://github.com/tailscale/tailscale/issues/1830
			continue
		case "Egg":
			// Not applicable.
			continue
		case "RunWebClient":
			// TODO(tailscale/corp#14335): Currently behind a feature flag.
			continue
		case "NetfilterKind":
			// Handled by TS_DEBUG_FIREWALL_MODE env var, we don't want to have
			// a CLI flag for this. The Pref is used by c2n.
			continue
		case "DriveShares":
			// Handled by the tailscale share subcommand, we don't want a CLI
			// flag for this.
			continue
		case "AdvertiseServices":
			// Handled by the tailscale serve subcommand, we don't want a
			// CLI flag for this.
			continue
		case "InternalExitNodePrior":
			// Used internally by LocalBackend as part of exit node usage toggling.
			// No CLI flag for this.
			continue
		case "AutoExitNode":
			// Handled by tailscale {set,up} --exit-node=auto:any.
			continue
		case "LinuxPacketMarks":
			// Configured via three separate flags: --linux-fwmark-mask,
			// --linux-subnet-route-mark, --linux-bypass-mark
			continue
		}
		t.Errorf("unexpected new ipn.Pref field %q is not handled by up.go (see addPrefFlagMapping and checkForAccidentalSettingReverts)", prefName)
	}
}

func TestFlagAppliesToOS(t *testing.T) {
	for _, goos := range geese {
		var upArgs upArgsT
		fs := newUpFlagSet(goos, &upArgs, "up")
		fs.VisitAll(func(f *flag.Flag) {
			if !flagAppliesToOS(f.Name, goos) {
				t.Errorf("flagAppliesToOS(%q, %q) = false but found in %s set", f.Name, goos, goos)
			}
		})
	}
}

func TestUpdatePrefs(t *testing.T) {
	tests := []struct {
		name     string
		flags    []string // argv to be parsed into env.flagSet and env.upArgs
		curPrefs *ipn.Prefs
		env      upCheckEnv // empty goos means "linux"

		// sshOverTailscale specifies if the cmd being run over SSH over Tailscale.
		// It is used to test the --accept-risks flag.
		sshOverTailscale bool

		// checkUpdatePrefsMutations, if non-nil, is run with the new prefs after
		// updatePrefs might've mutated them (from applyImplicitPrefs).
		checkUpdatePrefsMutations func(t *testing.T, newPrefs *ipn.Prefs)

		wantSimpleUp   bool
		wantJustEditMP *ipn.MaskedPrefs
		wantErrSubtr   string
	}{
		{
			name:         "bare_up_means_up",
			flags:        []string{},
			curPrefs:     ipn.NewPrefs(),
			wantSimpleUp: false, // user profile not set, so no simple up
		},
		{
			name:  "just_up",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				Persist:    &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
			},
			env: upCheckEnv{
				backendState: "Stopped",
			},
			wantSimpleUp: true,
		},
		{
			name:     "just_up_needs_login_default_prefs",
			flags:    []string{},
			curPrefs: ipn.NewPrefs(),
			env: upCheckEnv{
				backendState: "NeedsLogin",
			},
			wantSimpleUp: false,
		},
		{
			name:  "just_up_needs_login_losing_prefs",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				// defaults:
				ControlURL:    ipn.DefaultControlURL,
				WantRunning:   false,
				NetfilterMode: preftype.NetfilterOn,
				// non-default:
				CorpDNS: false,
			},
			env: upCheckEnv{
				backendState: "NeedsLogin",
			},
			wantSimpleUp: false,
			wantErrSubtr: "tailscale up --accept-dns=false",
		},
		{
			name:  "just_edit",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				Persist:    &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
		},
		{
			name:  "just_edit_reset",
			flags: []string{"--reset"},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				Persist:    &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
			},
			env: upCheckEnv{backendState: "Running"},
			wantJustEditMP: &ipn.MaskedPrefs{
				AdvertiseRoutesSet:        true,
				AdvertiseTagsSet:          true,
				AppConnectorSet:           true,
				ControlURLSet:             true,
				CorpDNSSet:                true,
				ExitNodeAllowLANAccessSet: true,
				ExitNodeIDSet:             true,
				ExitNodeIPSet:             true,
				HostnameSet:               true,
				NetfilterModeSet:          true,
				NoSNATSet:                 true,
				NoStatefulFilteringSet:    true,
				OperatorUserSet:           true,
				PostureCheckingSet:        true,
				RouteAllSet:               true,
				RunSSHSet:                 true,
				ShieldsUpSet:              true,
				WantRunningSet:            true,
			},
		},
		{
			name:  "control_synonym",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: "https://login.tailscale.com",
				Persist:    &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
		},
		{
			name:  "change_login_server",
			flags: []string{"--login-server=https://localhost:1000"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
			wantErrSubtr:   "can't change --login-server without --force-reauth",
		},
		{
			name:  "change_tags",
			flags: []string{"--advertise-tags=tag:foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			env: upCheckEnv{backendState: "Running"},
		},
		{
			// Issue 3808: explicitly empty --operator= should clear value.
			name:  "explicit_empty_operator",
			flags: []string{"--operator="},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				OperatorUser:        "somebody",
				NoStatefulFiltering: opt.NewBool(true),
			},
			env: upCheckEnv{user: "somebody", backendState: "Running"},
			wantJustEditMP: &ipn.MaskedPrefs{
				OperatorUserSet: true,
				WantRunningSet:  true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, prefs *ipn.Prefs) {
				if prefs.OperatorUser != "" {
					t.Errorf("operator sent to backend should be empty; got %q", prefs.OperatorUser)
				}
			},
		},
		{
			name:  "enable_ssh",
			flags: []string{"--ssh"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if !newPrefs.RunSSH {
					t.Errorf("RunSSH not set to true")
				}
			},
			env: upCheckEnv{backendState: "Running"},
		},
		{
			name:  "disable_ssh",
			flags: []string{"--ssh=false"},
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				RunSSH:              true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if newPrefs.RunSSH {
					t.Errorf("RunSSH not set to false")
				}
			},
			env: upCheckEnv{backendState: "Running", upArgs: upArgsT{
				runSSH: true,
			}},
		},
		{
			name:             "disable_ssh_over_ssh_no_risk",
			flags:            []string{"--ssh=false"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				RunSSH:              true,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if !newPrefs.RunSSH {
					t.Errorf("RunSSH not set to true")
				}
			},
			env:          upCheckEnv{backendState: "Running"},
			wantErrSubtr: "aborted, no changes made",
		},
		{
			name:             "enable_ssh_over_ssh_no_risk",
			flags:            []string{"--ssh=true"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if !newPrefs.RunSSH {
					t.Errorf("RunSSH not set to true")
				}
			},
			env:          upCheckEnv{backendState: "Running"},
			wantErrSubtr: "aborted, no changes made",
		},
		{
			name:             "enable_ssh_over_ssh",
			flags:            []string{"--ssh=true", "--accept-risk=lose-ssh"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if !newPrefs.RunSSH {
					t.Errorf("RunSSH not set to true")
				}
			},
			env: upCheckEnv{backendState: "Running"},
		},
		{
			name:             "disable_ssh_over_ssh",
			flags:            []string{"--ssh=false", "--accept-risk=lose-ssh"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				Persist:             &persist.Persist{UserProfile: tailcfg.UserProfile{LoginName: "crawshaw.github"}},
				CorpDNS:             true,
				RunSSH:              true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				RunSSHSet:      true,
				WantRunningSet: true,
			},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if newPrefs.RunSSH {
					t.Errorf("RunSSH not set to false")
				}
			},
			env: upCheckEnv{backendState: "Running"},
		},
		{
			name:             "force_reauth_over_ssh_no_risk",
			flags:            []string{"--force-reauth"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			env:          upCheckEnv{backendState: "Running"},
			wantErrSubtr: "aborted, no changes made",
		},
		{
			name:             "force_reauth_over_ssh",
			flags:            []string{"--force-reauth", "--accept-risk=lose-ssh"},
			sshOverTailscale: true,
			curPrefs: &ipn.Prefs{
				ControlURL:          "https://login.tailscale.com",
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: nil,
			env:            upCheckEnv{backendState: "Running"},
		},
		{
			name:  "advertise_connector",
			flags: []string{"--advertise-connector"},
			curPrefs: &ipn.Prefs{
				ControlURL:          ipn.DefaultControlURL,
				CorpDNS:             true,
				NetfilterMode:       preftype.NetfilterOn,
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				AppConnectorSet: true,
				WantRunningSet:  true,
			},
			env: upCheckEnv{backendState: "Running"},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if !newPrefs.AppConnector.Advertise {
					t.Errorf("prefs.AppConnector.Advertise not set")
				}
			},
		},
		{
			name:  "no_advertise_connector",
			flags: []string{"--advertise-connector=false"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,
				NetfilterMode: preftype.NetfilterOn,
				AppConnector: ipn.AppConnectorPrefs{
					Advertise: true,
				},
				NoStatefulFiltering: opt.NewBool(true),
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				AppConnectorSet: true,
				WantRunningSet:  true,
			},
			env: upCheckEnv{backendState: "Running"},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if newPrefs.AppConnector.Advertise {
					t.Errorf("prefs.AppConnector.Advertise not unset")
				}
			},
		},
		{
			name:  "auto_exit_node",
			flags: []string{"--exit-node=auto:any"},
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				CorpDNS:       true,                 // enabled by [ipn.NewPrefs] by default
				NetfilterMode: preftype.NetfilterOn, // enabled by [ipn.NewPrefs] by default
			},
			wantJustEditMP: &ipn.MaskedPrefs{
				WantRunningSet:  true, // enabled by default for tailscale up
				AutoExitNodeSet: true,
				ExitNodeIDSet:   true, // we want ExitNodeID cleared
				ExitNodeIPSet:   true, // same for ExitNodeIP
			},
			env: upCheckEnv{backendState: "Running"},
			checkUpdatePrefsMutations: func(t *testing.T, newPrefs *ipn.Prefs) {
				if newPrefs.AutoExitNode != ipn.AnyExitNode {
					t.Errorf("AutoExitNode: got %q; want %q", newPrefs.AutoExitNode, ipn.AnyExitNode)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sshOverTailscale {
				tstest.Replace(t, &getSSHClientEnvVar, func() string { return "100.100.100.100 1 1" })
			} else if isSSHOverTailscale() {
				// The test is being executed over a "real" tailscale SSH
				// session, but sshOverTailscale is unset. Make the test appear
				// as if it's not over tailscale SSH.
				tstest.Replace(t, &getSSHClientEnvVar, func() string { return "" })
			}
			if tt.env.goos == "" {
				tt.env.goos = "linux"
			}
			tt.env.flagSet = newUpFlagSet(tt.env.goos, &tt.env.upArgs, "up")
			flags := CleanUpArgs(tt.flags)
			if err := tt.env.flagSet.Parse(flags); err != nil {
				t.Fatal(err)
			}

			newPrefs, err := prefsFromUpArgs(tt.env.upArgs, t.Logf, new(ipnstate.Status), tt.env.goos)
			if err != nil {
				t.Fatal(err)
			}
			simpleUp, justEditMP, err := updatePrefs(newPrefs, tt.curPrefs, tt.env)
			if err != nil {
				if tt.wantErrSubtr != "" {
					if !strings.Contains(err.Error(), tt.wantErrSubtr) {
						t.Fatalf("want error %q, got: %v", tt.wantErrSubtr, err)
					}
					return
				}
				t.Fatal(err)
			} else if tt.wantErrSubtr != "" {
				t.Fatalf("want error %q, got nil", tt.wantErrSubtr)
			}
			if tt.checkUpdatePrefsMutations != nil {
				tt.checkUpdatePrefsMutations(t, newPrefs)
			}
			if simpleUp != tt.wantSimpleUp {
				t.Fatalf("simpleUp=%v, want %v", simpleUp, tt.wantSimpleUp)
			}
			var oldEditPrefs ipn.Prefs
			if justEditMP != nil {
				oldEditPrefs = justEditMP.Prefs
				justEditMP.Prefs = ipn.Prefs{} // uninteresting
			}
			if !reflect.DeepEqual(justEditMP, tt.wantJustEditMP) {
				t.Logf("justEditMP != wantJustEditMP; following diff omits the Prefs field, which was \n%v", logger.AsJSON(oldEditPrefs))
				t.Fatalf("justEditMP: %v\n\n: ", cmp.Diff(justEditMP, tt.wantJustEditMP, cmpIP))
			}
		})
	}
}

var cmpIP = cmp.Comparer(func(a, b netip.Addr) bool {
	return a == b
})

func TestCleanUpArgs(t *testing.T) {
	type S = []string
	c := qt.New(t)
	tests := []struct {
		in   []string
		want []string
	}{
		{in: S{"something"}, want: S{"something"}},
		{in: S{}, want: S{}},
		{in: S{"--authkey=0"}, want: S{"--auth-key=0"}},
		{in: S{"a", "--authkey=1", "b"}, want: S{"a", "--auth-key=1", "b"}},
		{in: S{"a", "--auth-key=2", "b"}, want: S{"a", "--auth-key=2", "b"}},
		{in: S{"a", "-authkey=3", "b"}, want: S{"a", "--auth-key=3", "b"}},
		{in: S{"a", "-auth-key=4", "b"}, want: S{"a", "-auth-key=4", "b"}},
		{in: S{"a", "--authkey", "5", "b"}, want: S{"a", "--auth-key", "5", "b"}},
		{in: S{"a", "-authkey", "6", "b"}, want: S{"a", "--auth-key", "6", "b"}},
		{in: S{"a", "authkey", "7", "b"}, want: S{"a", "authkey", "7", "b"}},
		{in: S{"--authkeyexpiry", "8"}, want: S{"--authkeyexpiry", "8"}},
		{in: S{"--auth-key-expiry", "9"}, want: S{"--auth-key-expiry", "9"}},

		{in: S{"--posture-checking"}, want: S{"--report-posture"}},
		{in: S{"-posture-checking"}, want: S{"--report-posture"}},
		{in: S{"--posture-checking=nein"}, want: S{"--report-posture=nein"}},
	}

	for _, tt := range tests {
		got := CleanUpArgs(tt.in)
		c.Assert(got, qt.DeepEquals, tt.want)
	}
}

func TestUpWorthWarning(t *testing.T) {
	if !upWorthyWarning(healthmsg.WarnAcceptRoutesOff) {
		t.Errorf("WarnAcceptRoutesOff of %q should be worth warning", healthmsg.WarnAcceptRoutesOff)
	}
	if !upWorthyWarning(healthmsg.TailscaleSSHOnBut + "some problem") {
		t.Errorf("want true for SSH problems")
	}
	if upWorthyWarning("not in map poll") {
		t.Errorf("want false for other misc errors")
	}
}

func TestParseNLArgs(t *testing.T) {
	tcs := []struct {
		name              string
		input             []string
		parseKeys         bool
		parseDisablements bool

		wantErr          error
		wantKeys         []tka.Key
		wantDisablements [][]byte
	}{
		{
			name:              "empty",
			input:             nil,
			parseKeys:         true,
			parseDisablements: true,
		},
		{
			name:      "key no votes",
			input:     []string{"nlpub:" + strings.Repeat("00", 32)},
			parseKeys: true,
			wantKeys:  []tka.Key{{Kind: tka.Key25519, Votes: 1, Public: bytes.Repeat([]byte{0}, 32)}},
		},
		{
			name:      "key with votes",
			input:     []string{"nlpub:" + strings.Repeat("01", 32) + "?5"},
			parseKeys: true,
			wantKeys:  []tka.Key{{Kind: tka.Key25519, Votes: 5, Public: bytes.Repeat([]byte{1}, 32)}},
		},
		{
			name:              "disablements",
			input:             []string{"disablement:" + strings.Repeat("02", 32), "disablement-secret:" + strings.Repeat("03", 32)},
			parseDisablements: true,
			wantDisablements:  [][]byte{bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)},
		},
		{
			name:      "disablements not allowed",
			input:     []string{"disablement:" + strings.Repeat("02", 32)},
			parseKeys: true,
			wantErr:   fmt.Errorf("parsing key 1: key hex string doesn't have expected type prefix tlpub:"),
		},
		{
			name:              "keys not allowed",
			input:             []string{"nlpub:" + strings.Repeat("02", 32)},
			parseDisablements: true,
			wantErr:           fmt.Errorf("parsing argument 1: expected value with \"disablement:\" or \"disablement-secret:\" prefix, got %q", "nlpub:0202020202020202020202020202020202020202020202020202020202020202"),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			keys, disablements, err := parseNLArgs(tc.input, tc.parseKeys, tc.parseDisablements)
			if (tc.wantErr == nil && err != nil) ||
				(tc.wantErr != nil && err == nil) ||
				(tc.wantErr != nil && err != nil && tc.wantErr.Error() != err.Error()) {
				t.Fatalf("parseNLArgs(%v).err = %v, want %v", tc.input, err, tc.wantErr)
			}

			if !reflect.DeepEqual(keys, tc.wantKeys) {
				t.Errorf("keys = %v, want %v", keys, tc.wantKeys)
			}
			if !reflect.DeepEqual(disablements, tc.wantDisablements) {
				t.Errorf("disablements = %v, want %v", disablements, tc.wantDisablements)
			}
		})
	}
}

// makeQuietContinueOnError modifies c recursively to make all the
// flagsets have error mode flag.ContinueOnError and not
// spew all over stderr.
func makeQuietContinueOnError(c *ffcli.Command) {
	if c.FlagSet != nil {
		c.FlagSet.Init(c.Name, flag.ContinueOnError)
		c.FlagSet.Usage = func() {}
		c.FlagSet.SetOutput(io.Discard)
	}
	c.UsageFunc = func(*ffcli.Command) string { return "" }
	for _, sub := range c.Subcommands {
		makeQuietContinueOnError(sub)
	}
}

// see tailscale/tailscale#6813
func TestNoDups(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "dup-boolean",
			args: []string{"up", "--json", "--json"},
			want: "error parsing commandline arguments: invalid boolean flag json: flag provided multiple times",
		},
		{
			name: "dup-string",
			args: []string{"up", "--hostname=foo", "--hostname=bar"},
			want: "error parsing commandline arguments: invalid value \"bar\" for flag -hostname: flag provided multiple times",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd()
			makeQuietContinueOnError(cmd)
			err := cmd.Parse(tt.args)
			if got := fmt.Sprint(err); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHelpAlias(t *testing.T) {
	var stdout, stderr bytes.Buffer
	tstest.Replace[io.Writer](t, &Stdout, &stdout)
	tstest.Replace[io.Writer](t, &Stderr, &stderr)

	gotExit0 := false
	defer func() {
		if !gotExit0 {
			t.Error("expected os.Exit(0) to be called")
			return
		}
		if !strings.Contains(stderr.String(), "SUBCOMMANDS") {
			t.Errorf("expected help output to contain SUBCOMMANDS; got stderr=%q; stdout=%q", stderr.String(), stdout.String())
		}
	}()
	defer func() {
		if e := recover(); e != nil {
			if strings.Contains(fmt.Sprint(e), "unexpected call to os.Exit(0)") {
				gotExit0 = true
			} else {
				t.Errorf("unexpected panic: %v", e)
			}
		}
	}()
	err := Run([]string{"help"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestDocs(t *testing.T) {
	root := newRootCmd()
	check := func(t *testing.T, c *ffcli.Command) {
		shortVerb, _, ok := strings.Cut(c.ShortHelp, " ")
		if !ok || shortVerb == "" {
			t.Errorf("couldn't find verb+space in ShortHelp")
		} else {
			if strings.HasSuffix(shortVerb, ".") {
				t.Errorf("ShortHelp shouldn't end in period; got %q", c.ShortHelp)
			}
			if b := shortVerb[0]; b >= 'a' && b <= 'z' {
				t.Errorf("ShortHelp should start with upper-case letter; got %q", c.ShortHelp)
			}
			if strings.HasSuffix(shortVerb, "s") && shortVerb != "Does" {
				t.Errorf("verb %q ending in 's' is unexpected, from %q", shortVerb, c.ShortHelp)
			}
		}

		name := t.Name()
		wantPfx := strings.ReplaceAll(strings.TrimPrefix(name, "TestDocs/"), "/", " ")
		switch name {
		case "TestDocs/tailscale/completion/bash",
			"TestDocs/tailscale/completion/zsh":
			wantPfx = "" // special-case exceptions
		}
		if !strings.HasPrefix(c.ShortUsage, wantPfx) {
			t.Errorf("ShortUsage should start with %q; got %q", wantPfx, c.ShortUsage)
		}
	}

	var walk func(t *testing.T, c *ffcli.Command)
	walk = func(t *testing.T, c *ffcli.Command) {
		t.Run(c.Name, func(t *testing.T) {
			check(t, c)
			for _, sub := range c.Subcommands {
				walk(t, sub)
			}
		})
	}
	walk(t, root)
}

func TestUpResolves(t *testing.T) {
	const testARN = "arn:aws:ssm:us-east-1:123456789012:parameter/my-parameter"
	undo := tailscale.HookResolveValueFromParameterStore.SetForTest(func(_ context.Context, valueOrARN string) (string, error) {
		if valueOrARN == testARN {
			return "resolved-value", nil
		}
		return valueOrARN, nil
	})
	defer undo()

	const content = "file-content"
	fpath := filepath.Join(t.TempDir(), "testfile")
	if err := os.WriteFile(fpath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name string
		arg  string
		want string
	}{
		{"parameter_store", testARN, "resolved-value"},
		{"file", "file:" + fpath, "file-content"},
	}

	for _, tt := range testCases {
		t.Run(tt.name+"_auth_key", func(t *testing.T) {
			args := upArgsT{authKeyOrFile: tt.arg}
			got, err := args.getAuthKey(t.Context())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})

		t.Run(tt.name+"_client_secret", func(t *testing.T) {
			args := upArgsT{clientSecretOrFile: tt.arg}
			got, err := args.getClientSecret(t.Context())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})

		t.Run(tt.name+"_id_token", func(t *testing.T) {
			args := upArgsT{idTokenOrFile: tt.arg}
			got, err := args.getIDToken(t.Context())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("passthrough", func(t *testing.T) {
		args := upArgsT{authKeyOrFile: "tskey-abcd1234"}
		got, err := args.getAuthKey(t.Context())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "tskey-abcd1234" {
			t.Errorf("got %q, want %q", got, "tskey-abcd1234")
		}
	})
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "arm64",
		WantDeps: set.Of(
			"tailscale.com/feature/capture/dissector", // want the Lua by default
		),
		BadDeps: map[string]string{
			"tailscale.com/feature/capture": "don't link capture code",
			"tailscale.com/net/packet":      "why we passing packets in the CLI?",
			"tailscale.com/net/flowtrack":   "why we tracking flows in the CLI?",
		},
	}.Check(t)
}

func TestDepsNoCapture(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "arm64",
		Tags:   "ts_omit_capture",
		BadDeps: map[string]string{
			"tailscale.com/feature/capture":           "don't link capture code",
			"tailscale.com/feature/capture/dissector": "don't like the Lua",
		},
	}.Check(t)

}

func TestSanitizeWriter(t *testing.T) {
	buf := new(bytes.Buffer)
	w := sanitizeOutput(buf)

	in := []byte(`my auth key is tskey-auth-abc123-def456 and tskey-foo, what's yours?`)
	want := []byte(`my auth key is tskey-XXXXXXXXXXXXXXXXXX and tskey-XXX, what's yours?`)
	n, err := w.Write(in)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(in) {
		t.Errorf("unexpected write length %d, want %d", n, len(in))
	}
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("unexpected sanitized content\ngot: %q\nwant: %q", got, want)
	}
}

func TestParseLinuxPacketMarks(t *testing.T) {
	tests := []struct {
		name            string
		fwmarkMask      string
		subnetRouteMark string
		bypassMark      string
		want            *preftype.LinuxPacketMarks
		wantErr         bool
		errContains     string
	}{
		{
			name:            "all empty returns nil",
			fwmarkMask:      "",
			subnetRouteMark: "",
			bypassMark:      "",
			want:            nil,
			wantErr:         false,
		},
		{
			name:            "valid hex values",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x80000",
			want: &preftype.LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantErr: false,
		},
		{
			name:            "valid decimal values",
			fwmarkMask:      "16711680",
			subnetRouteMark: "262144",
			bypassMark:      "524288",
			want: &preftype.LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantErr: false,
		},
		{
			name:            "mixed hex and decimal",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "262144",
			bypassMark:      "0x80000",
			want: &preftype.LinuxPacketMarks{
				FwmarkMask:      0xff0000,
				SubnetRouteMark: 0x40000,
				BypassMark:      0x80000,
			},
			wantErr: false,
		},
		{
			name:            "only mask specified",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "",
			bypassMark:      "",
			want:            nil,
			wantErr:         true,
			errContains:     "all three Linux packet mark flags must be specified together",
		},
		{
			name:            "only subnet mark specified",
			fwmarkMask:      "",
			subnetRouteMark: "0x40000",
			bypassMark:      "",
			want:            nil,
			wantErr:         true,
			errContains:     "all three Linux packet mark flags must be specified together",
		},
		{
			name:            "mask and subnet mark but no bypass",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "0x40000",
			bypassMark:      "",
			want:            nil,
			wantErr:         true,
			errContains:     "all three Linux packet mark flags must be specified together",
		},
		{
			name:            "invalid hex format",
			fwmarkMask:      "0xZZZZZZ",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x80000",
			want:            nil,
			wantErr:         true,
			errContains:     "invalid fwmark mask value",
		},
		{
			name:            "invalid decimal format",
			fwmarkMask:      "abc",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x80000",
			want:            nil,
			wantErr:         true,
			errContains:     "invalid fwmark mask value",
		},
		{
			name:            "subnet mark not covered by mask",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "0x1000000",
			bypassMark:      "0x80000",
			want:            nil,
			wantErr:         true,
			errContains:     "subnet route mark",
		},
		{
			name:            "bypass mark not covered by mask",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x1000000",
			want:            nil,
			wantErr:         true,
			errContains:     "bypass mark",
		},
		{
			name:            "subnet and bypass marks are the same",
			fwmarkMask:      "0xff0000",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x40000",
			want:            nil,
			wantErr:         true,
			errContains:     "must differ",
		},
		{
			name:            "zero mask",
			fwmarkMask:      "0",
			subnetRouteMark: "0x40000",
			bypassMark:      "0x80000",
			want:            nil,
			wantErr:         true,
			errContains:     "fwmark mask must be non-zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLinuxPacketMarks(tt.fwmarkMask, tt.subnetRouteMark, tt.bypassMark)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLinuxPacketMarks() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseLinuxPacketMarks() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if !tt.wantErr {
				if !equalLinuxPacketMarks(got, tt.want) {
					t.Errorf("parseLinuxPacketMarks() = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func equalLinuxPacketMarks(a, b *preftype.LinuxPacketMarks) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.FwmarkMask == b.FwmarkMask &&
		a.SubnetRouteMark == b.SubnetRouteMark &&
		a.BypassMark == b.BypassMark
}
