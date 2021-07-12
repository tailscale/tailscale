// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
)

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
		fs := newUpFlagSet(goos, &upArgs)
		fs.VisitAll(func(f *flag.Flag) {
			mp := new(ipn.MaskedPrefs)
			updateMaskedPrefsFromUpFlag(mp, f.Name)
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

		curExitNodeIP netaddr.IP
		curUser       string // os.Getenv("USER") on the client side
		goos          string // empty means "linux"

		want string
	}{
		{
			name:  "bare_up_means_up",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
			},
			want: "",
		},
		{
			name:  "losing_hostname",
			flags: []string{"--accept-dns"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      false,
				Hostname:         "foo",
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AllowSingleHosts: true,
			},
			want: accidentalUpPrefix + " --accept-dns --hostname=foo",
		},
		{
			name:  "hostname_changing_explicitly",
			flags: []string{"--hostname=bar"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AllowSingleHosts: true,
				Hostname:         "foo",
			},
			want: "",
		},
		{
			name:  "hostname_changing_empty_explicitly",
			flags: []string{"--hostname="},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AllowSingleHosts: true,
				Hostname:         "foo",
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
				ControlURL:       ipn.DefaultControlURL,
				OperatorUser:     "alice",
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --hostname=foo --operator=alice",
		},
		{
			name:  "implicit_operator_matches_shell_user",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				OperatorUser:     "alice",
			},
			curUser: "alice",
			want:    "",
		},
		{
			name:  "error_advertised_routes_exit_node_removed",
			flags: []string{"--advertise-routes=10.0.42.0/24"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			want: accidentalUpPrefix + " --advertise-routes=10.0.42.0/24 --advertise-exit-node",
		},
		{
			name:  "advertised_routes_exit_node_removed_explicit",
			flags: []string{"--advertise-routes=10.0.42.0/24", "--advertise-exit-node=false"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			want: "",
		},
		{
			name:  "advertised_routes_includes_the_0_routes", // but no --advertise-exit-node
			flags: []string{"--advertise-routes=11.1.43.0/24,0.0.0.0/0,::/0"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			want: "",
		},
		{
			name:  "advertise_exit_node", // Issue 1859
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
			},
			want: "",
		},
		{
			name:  "advertise_exit_node_over_existing_routes",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,

				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "advertise_exit_node_over_existing_routes_and_exit_node",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "exit_node_clearing", // Issue 1777
			flags: []string{"--exit-node="},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,

				ExitNodeID: "fooID",
			},
			want: "",
		},
		{
			name:  "remove_all_implicit",
			flags: []string{"--force-reauth"},
			curPrefs: &ipn.Prefs{
				WantRunning:      true,
				ControlURL:       ipn.DefaultControlURL,
				RouteAll:         true,
				AllowSingleHosts: false,
				ExitNodeIP:       netaddr.MustParseIP("100.64.5.6"),
				CorpDNS:          false,
				ShieldsUp:        true,
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
				Hostname:         "myhostname",
				ForceDaemon:      true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.0.0/16"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
				NetfilterMode: preftype.NetfilterNoDivert,
				OperatorUser:  "alice",
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --force-reauth --accept-dns=false --accept-routes --advertise-exit-node --advertise-routes=10.0.0.0/16 --advertise-tags=tag:foo,tag:bar --exit-node=100.64.5.6 --host-routes=false --hostname=myhostname --netfilter-mode=nodivert --operator=alice --shields-up",
		},
		{
			name:  "remove_all_implicit_except_hostname",
			flags: []string{"--hostname=newhostname"},
			curPrefs: &ipn.Prefs{
				WantRunning:      true,
				ControlURL:       ipn.DefaultControlURL,
				RouteAll:         true,
				AllowSingleHosts: false,
				ExitNodeIP:       netaddr.MustParseIP("100.64.5.6"),
				CorpDNS:          false,
				ShieldsUp:        true,
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
				Hostname:         "myhostname",
				ForceDaemon:      true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.0.0/16"),
				},
				NetfilterMode: preftype.NetfilterNoDivert,
				OperatorUser:  "alice",
			},
			curUser: "eve",
			want:    accidentalUpPrefix + " --hostname=newhostname --accept-dns=false --accept-routes --advertise-routes=10.0.0.0/16 --advertise-tags=tag:foo,tag:bar --exit-node=100.64.5.6 --host-routes=false --netfilter-mode=nodivert --operator=alice --shields-up",
		},
		{
			name:  "loggedout_is_implicit",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				LoggedOut:        true,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
			},
			want: "", // not an error. LoggedOut is implicit.
		},
		{
			// Test that a pre-1.8 version of Tailscale with bogus NoSNAT pref
			// values is able to enable exit nodes without warnings.
			name:  "make_windows_exit_node",
			flags: []string{"--advertise-exit-node"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,

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
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,

				NetfilterMode: preftype.NetfilterNoDivert, // we never had this bug, but pretend it got set non-zero on Windows somehow
			},
			goos: "windows",
			want: "", // not an error
		},
		{
			name:  "operator_losing_routes_step1", // https://twitter.com/EXPbits/status/1390418145047887877
			flags: []string{"--operator=expbits"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			want: accidentalUpPrefix + " --operator=expbits --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:  "operator_losing_routes_step2", // https://twitter.com/EXPbits/status/1390418145047887877
			flags: []string{"--operator=expbits", "--advertise-routes=1.2.0.0/16"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			want: accidentalUpPrefix + " --advertise-routes=1.2.0.0/16 --operator=expbits --advertise-exit-node",
		},
		{
			name:  "errors_preserve_explicit_flags",
			flags: []string{"--reset", "--force-reauth=false", "--authkey=secretrand"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      false,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
				AllowSingleHosts: true,

				Hostname: "foo",
			},
			want: accidentalUpPrefix + " --authkey=secretrand --force-reauth=false --reset --hostname=foo",
		},
		{
			name:  "error_exit_node_omit_with_ip_pref",
			flags: []string{"--hostname=foo"},
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,

				ExitNodeIP: netaddr.MustParseIP("100.64.5.4"),
			},
			want: accidentalUpPrefix + " --hostname=foo --exit-node=100.64.5.4",
		},
		{
			name:          "error_exit_node_omit_with_id_pref",
			flags:         []string{"--hostname=foo"},
			curExitNodeIP: netaddr.MustParseIP("100.64.5.7"),
			curPrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,

				ExitNodeID: "some_stable_id",
			},
			want: accidentalUpPrefix + " --hostname=foo --exit-node=100.64.5.7",
		},
		{
			name:  "ignore_login_server_synonym",
			flags: []string{"--login-server=https://controlplane.tailscale.com"},
			curPrefs: &ipn.Prefs{
				ControlURL:       "https://login.tailscale.com",
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
			},
			want: "", // not an error
		},
		{
			name:  "ignore_login_server_synonym_on_other_change",
			flags: []string{"--netfilter-mode=off"},
			curPrefs: &ipn.Prefs{
				ControlURL:       "https://login.tailscale.com",
				AllowSingleHosts: true,
				CorpDNS:          false,
				NetfilterMode:    preftype.NetfilterOn,
			},
			want: accidentalUpPrefix + " --netfilter-mode=off --accept-dns=false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goos := "linux"
			if tt.goos != "" {
				goos = tt.goos
			}
			var upArgs upArgsT
			flagSet := newUpFlagSet(goos, &upArgs)
			flagSet.Parse(tt.flags)
			newPrefs, err := prefsFromUpArgs(upArgs, t.Logf, new(ipnstate.Status), goos)
			if err != nil {
				t.Fatal(err)
			}
			applyImplicitPrefs(newPrefs, tt.curPrefs, tt.curUser)
			var got string
			if err := checkForAccidentalSettingReverts(newPrefs, tt.curPrefs, upCheckEnv{
				goos:          goos,
				flagSet:       flagSet,
				curExitNodeIP: tt.curExitNodeIP,
			}); err != nil {
				got = err.Error()
			}
			if strings.TrimSpace(got) != tt.want {
				t.Errorf("unexpected result\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}

func upArgsFromOSArgs(goos string, flagArgs ...string) (args upArgsT) {
	fs := newUpFlagSet(goos, &args)
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
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				NoSNAT:           false,
				NetfilterMode:    preftype.NetfilterOn,
				CorpDNS:          true,
				AllowSingleHosts: true,
			},
		},
		{
			name: "default_windows",
			goos: "windows",
			args: upArgsFromOSArgs("windows"),
			want: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				CorpDNS:          true,
				AllowSingleHosts: true,
				NetfilterMode:    preftype.NetfilterOn,
			},
		},
		{
			name: "advertise_default_route",
			args: upArgsFromOSArgs("linux", "--advertise-exit-node"),
			want: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				AllowSingleHosts: true,
				CorpDNS:          true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
				NetfilterMode: preftype.NetfilterOn,
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
			wantErr: `invalid IP address "foo" for --exit-node: ParseIP("foo"): unable to parse IP`,
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
				hostname: strings.Repeat("a", 300),
			},
			wantErr: `hostname too long: 300 bytes (max 256)`,
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
				TailscaleIPs: []netaddr.IP{netaddr.MustParseIP("100.105.106.107")},
			},
			wantErr: `cannot use 100.105.106.107 as the exit node as it is a local IP address to this machine, did you mean --advertise-exit-node?`,
		},
		{
			name: "warn_linux_netfilter_nodivert",
			goos: "linux",
			args: upArgsT{
				netfilterMode: "nodivert",
			},
			wantWarn: "netfilter=nodivert; add iptables calls to ts-* chains manually.",
			want: &ipn.Prefs{
				WantRunning:   true,
				NetfilterMode: preftype.NetfilterNoDivert,
				NoSNAT:        true,
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
				WantRunning:   true,
				NetfilterMode: preftype.NetfilterOff,
				NoSNAT:        true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnBuf bytes.Buffer
			warnf := func(format string, a ...interface{}) {
				fmt.Fprintf(&warnBuf, format, a...)
			}
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			st := tt.st
			if st == nil {
				st = new(ipnstate.Status)
			}
			got, err := prefsFromUpArgs(tt.args, warnf, st, goos)
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
			prefHasFlag[pref] = true
		}
	}

	prefType := reflect.TypeOf(ipn.Prefs{})
	for i := 0; i < prefType.NumField(); i++ {
		prefName := prefType.Field(i).Name
		if prefHasFlag[prefName] {
			continue
		}
		switch prefName {
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
		}
		t.Errorf("unexpected new ipn.Pref field %q is not handled by up.go (see addPrefFlagMapping and checkForAccidentalSettingReverts)", prefName)
	}
}

func TestFlagAppliesToOS(t *testing.T) {
	for _, goos := range geese {
		var upArgs upArgsT
		fs := newUpFlagSet(goos, &upArgs)
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

		wantSimpleUp   bool
		wantJustEditMP *ipn.MaskedPrefs
		wantErrSubtr   string
	}{
		{
			name:  "bare_up_means_up",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
			},
		},
		{
			name:  "just_up",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				Persist:    &persist.Persist{LoginName: "crawshaw.github"},
			},
			env: upCheckEnv{
				backendState: "Stopped",
			},
			wantSimpleUp: true,
		},
		{
			name:  "just_edit",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				Persist:    &persist.Persist{LoginName: "crawshaw.github"},
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
		},
		{
			name:  "control_synonym",
			flags: []string{},
			curPrefs: &ipn.Prefs{
				ControlURL: "https://login.tailscale.com",
				Persist:    &persist.Persist{LoginName: "crawshaw.github"},
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
		},
		{
			name:  "change_login_server",
			flags: []string{"--login-server=https://localhost:1000"},
			curPrefs: &ipn.Prefs{
				ControlURL:       "https://login.tailscale.com",
				Persist:          &persist.Persist{LoginName: "crawshaw.github"},
				AllowSingleHosts: true,
				CorpDNS:          true,
				NetfilterMode:    preftype.NetfilterOn,
			},
			env:            upCheckEnv{backendState: "Running"},
			wantSimpleUp:   true,
			wantJustEditMP: &ipn.MaskedPrefs{WantRunningSet: true},
			wantErrSubtr:   "can't change --login-server without --force-reauth",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env.goos == "" {
				tt.env.goos = "linux"
			}
			tt.env.flagSet = newUpFlagSet(tt.env.goos, &tt.env.upArgs)
			tt.env.flagSet.Parse(tt.flags)

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
			}
			if simpleUp != tt.wantSimpleUp {
				t.Fatalf("simpleUp=%v, want %v", simpleUp, tt.wantSimpleUp)
			}
			if justEditMP != nil {
				justEditMP.Prefs = ipn.Prefs{} // uninteresting
			}
			if !reflect.DeepEqual(justEditMP, tt.wantJustEditMP) {
				t.Fatalf("justEditMP: %v", cmp.Diff(justEditMP, tt.wantJustEditMP))
			}
		})
	}
}
