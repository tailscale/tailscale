// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"flag"
	"testing"

	"tailscale.com/ipn"
)

// Test that checkForAccidentalSettingReverts's updateMaskedPrefsFromUpFlag can handle
// all flags. This will panic if a new flag creeps in that's unhandled.
func TestUpdateMaskedPrefsFromUpFlag(t *testing.T) {
	mp := new(ipn.MaskedPrefs)
	upFlagSet.VisitAll(func(f *flag.Flag) {
		updateMaskedPrefsFromUpFlag(mp, f.Name)
	})
}

func TestCheckForAccidentalSettingReverts(t *testing.T) {
	f := func(flags ...string) map[string]bool {
		m := make(map[string]bool)
		for _, f := range flags {
			m[f] = true
		}
		return m
	}
	tests := []struct {
		name     string
		flagSet  map[string]bool
		curPrefs *ipn.Prefs
		mp       *ipn.MaskedPrefs
		want     string
	}{
		{
			name:    "bare_up_means_up",
			flagSet: f(),
			curPrefs: &ipn.Prefs{
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			},
			want: "",
		},
		{
			name:    "losing_hostname",
			flagSet: f("accept-dns"),
			curPrefs: &ipn.Prefs{
				WantRunning: false,
				Hostname:    "foo",
				CorpDNS:     true,
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
					CorpDNS:     true,
				},
				WantRunningSet: true,
				CorpDNSSet:     true,
			},
			want: `'tailscale up' without --reset requires all preferences with changing values to be explicitly mentioned; --hostname is not specified but its default value of "" differs from current value "foo"`,
		},
		{
			name:    "hostname_changing_explicitly",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
					Hostname:    "bar",
				},
				WantRunningSet: true,
				HostnameSet:    true,
			},
			want: "",
		},
		{
			name:    "hostname_changing_empty_explicitly",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
					Hostname:    "",
				},
				WantRunningSet: true,
				HostnameSet:    true,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if err := checkForAccidentalSettingReverts(tt.flagSet, tt.curPrefs, tt.mp); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("unexpected result\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}
