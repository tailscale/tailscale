// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/tstest"
)

func TestParse(t *testing.T) {
	tests := []struct {
		version string
		parsed  parsed
		want    bool
	}{
		{"1", parsed{Major: 1}, true},
		{"1.2", parsed{Major: 1, Minor: 2}, true},
		{"1.2.3", parsed{Major: 1, Minor: 2, Patch: 3}, true},
		{"1.2.3-4", parsed{Major: 1, Minor: 2, Patch: 3, ExtraCommits: 4}, true},
		{"1.2-4", parsed{Major: 1, Minor: 2, ExtraCommits: 4}, true},
		{"1.2.3-4-extra", parsed{Major: 1, Minor: 2, Patch: 3, ExtraCommits: 4}, true},
		{"1.2.3-4a-test", parsed{Major: 1, Minor: 2, Patch: 3}, true},
		{"1.2-extra", parsed{Major: 1, Minor: 2}, true},
		{"1.2.3-extra", parsed{Major: 1, Minor: 2, Patch: 3}, true},
		{"date.20200612", parsed{Datestamp: 20200612}, true},
		{"borkbork", parsed{}, false},
		{"1a.2.3", parsed{}, false},
		{"", parsed{}, false},
	}

	for _, test := range tests {
		gotParsed, got := parse(test.version)
		if got != test.want {
			t.Errorf("version(%q) = %v, want %v", test.version, got, test.want)
		}
		if diff := cmp.Diff(gotParsed, test.parsed); diff != "" {
			t.Errorf("parse(%q) diff (-got+want):\n%s", test.version, diff)
		}
		err := tstest.MinAllocsPerRun(t, 0, func() {
			gotParsed, got = parse(test.version)
		})
		if err != nil {
			t.Errorf("parse(%q): %v", test.version, err)
		}
	}
}

func TestAtLeast(t *testing.T) {
	tests := []struct {
		v, m string
		want bool
	}{
		{"1", "1", true},
		{"1.2", "1", true},
		{"1.2.3", "1", true},
		{"1.2.3-4", "1", true},
		{"0.98-0", "0.98", true},
		{"0.97.1-216", "0.98", false},
		{"0.94", "0.98", false},
		{"0.98", "0.98", true},
		{"0.98.0-0", "0.98", true},
		{"1.2.3-4", "1.2.4-4", false},
		{"1.2.3-4", "1.2.3-4", true},
		{"date.20200612", "date.20200612", true},
		{"date.20200701", "date.20200612", true},
		{"date.20200501", "date.20200612", false},
	}

	for _, test := range tests {
		got := AtLeast(test.v, test.m)
		if got != test.want {
			t.Errorf("AtLeast(%q, %q) = %v, want %v", test.v, test.m, got, test.want)
		}
	}
}
