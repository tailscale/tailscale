// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magic

import (
	"slices"
	"testing"
)

func TestParseDirACL(t *testing.T) {
	tests := []struct {
		name    string
		want    []string
		wantErr bool
	}{
		{"fserb", []string{"fserb"}, false},
		{"fserb+rhea", []string{"fserb", "rhea"}, false},
		{"Fserb+RHEA", []string{"fserb", "rhea"}, false},
		{"fserb+fserb", []string{"fserb"}, false},
		{"fserb+rhea+joe", []string{"fserb", "rhea", "joe"}, false},
		{"fserb@example.com+rhea", []string{"fserb@example.com", "rhea"}, false},

		{"", nil, true},
		{"+fserb", nil, true},
		{"fserb+", nil, true},
		{"fserb++rhea", nil, true},
		{"fserb rhea", nil, true},
		{"fserb!", nil, true},
		{"@example.com", nil, true},
		{"fserb@", nil, true},
		{"fserb@@example.com", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDirACL(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !slices.Equal(got.Users, tt.want) {
				t.Errorf("Users=%v, want %v", got.Users, tt.want)
			}
		})
	}
}

func TestMatches(t *testing.T) {
	const sharer = "fserb@example.com"
	tests := []struct {
		name      string
		dir       string
		peerLogin string
		want      bool
	}{
		{"sharer matches own dir", "fserb", sharer, true},
		{"sharer matches paired dir", "fserb+rhea", sharer, true},
		{"peer matches paired dir (short)", "fserb+rhea", "rhea@example.com", true},
		{"peer matches paired dir (email)", "fserb+rhea@example.com", "rhea@example.com", true},
		{"peer mismatch full email", "fserb+rhea@other.com", "rhea@example.com", false},
		{"peer not in dir", "fserb+rhea", "joe@example.com", false},
		{"sharer-not-in-name invalidates dir for peer", "rhea+joe", "rhea@example.com", false},
		{"sharer-not-in-name invalidates dir for sharer too", "rhea+joe", sharer, false},
		{"empty peer login", "fserb", "", false},
		{"three principal dir, peer ok", "fserb+rhea+joe", "joe@example.com", true},
		{"case-insensitive peer", "fserb+rhea", "RHEA@example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := ParseDirACL(tt.dir)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.dir, err)
			}
			got := acl.Matches(tt.peerLogin, sharer)
			if got != tt.want {
				t.Errorf("Matches(%q, %q)=%v, want %v", tt.peerLogin, sharer, got, tt.want)
			}
		})
	}
}
