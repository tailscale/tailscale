// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package drive

import (
	"testing"

	"tailscale.com/types/views"
)

func TestParseShareAccessNames(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{"joe+rhea", []string{"joe", "rhea"}},
		{"alice+joe+rhea", []string{"alice", "joe", "rhea"}},
		{"c++", nil},       // empty segments
		{"docs", nil},      // no '+'
		{"+leading", nil},  // empty first segment
		{"trailing+", nil}, // empty last segment
		{"a++b", nil},      // empty middle segment
		{"a+b", []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseShareAccessNames(tt.name)
			if tt.want == nil {
				if got != nil {
					t.Errorf("ParseShareAccessNames(%q) = %v, want nil", tt.name, got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("ParseShareAccessNames(%q) = %v, want %v", tt.name, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseShareAccessNames(%q)[%d] = %q, want %q", tt.name, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizeShareNameOrder(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"rhea+joe", "joe+rhea"},
		{"charlie+alice+bob", "alice+bob+charlie"},
		{"docs", "docs"},
		{"c++", "c++"},
		{"a+b", "a+b"}, // already sorted
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeShareNameOrder(tt.name)
			if got != tt.want {
				t.Errorf("NormalizeShareNameOrder(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsShareAccessibleByUser(t *testing.T) {
	tests := []struct {
		shareName string
		loginName string
		want      bool
	}{
		{"joe+rhea", "joe@example.com", true},
		{"joe+rhea", "rhea@example.com", true},
		{"joe+rhea", "alice@example.com", false},
		{"docs", "anyone@example.com", true}, // not a multi-user share
		{"c++", "anyone@example.com", true},  // not a multi-user share (empty segments)
		{"joe+rhea", "joe", true},            // no domain

		// name(domain) format
		{"alice(contractor)+bob", "alice@contractor.io", true},
		{"alice(contractor)+bob", "alice@example.com", false},   // wrong domain
		{"alice(contractor)+bob", "bob@example.com", true},      // bob has no domain qualifier
		{"alice(contractor)+bob", "charlie@example.com", false}, // not listed
	}
	for _, tt := range tests {
		t.Run(tt.shareName+"_"+tt.loginName, func(t *testing.T) {
			got := IsShareAccessibleByUser(tt.shareName, tt.loginName)
			if got != tt.want {
				t.Errorf("IsShareAccessibleByUser(%q, %q) = %v, want %v", tt.shareName, tt.loginName, got, tt.want)
			}
		})
	}
}

func TestLoginDisplayName(t *testing.T) {
	tests := []struct {
		loginName     string
		tailnetDomain string
		want          string
	}{
		{"alice@example.com", "example.com", "alice"},              // home domain
		{"alice@contractor.io", "example.com", "alice(contractor)"}, // foreign domain
		{"alice@example.com", "bob@gmail.com", "alice(example)"},   // shared domain tailnet
		{"alice", "example.com", "alice"},                           // no domain in login
		{"alice@foo.bar.com", "example.com", "alice(foo)"},         // multi-part domain
	}
	for _, tt := range tests {
		t.Run(tt.loginName+"_"+tt.tailnetDomain, func(t *testing.T) {
			got := LoginDisplayName(tt.loginName, tt.tailnetDomain)
			if got != tt.want {
				t.Errorf("LoginDisplayName(%q, %q) = %q, want %q", tt.loginName, tt.tailnetDomain, got, tt.want)
			}
		})
	}
}

func TestParseShareSegment(t *testing.T) {
	tests := []struct {
		input      string
		wantShort  string
		wantDomain string
	}{
		{"alice", "alice", ""},
		{"alice(company)", "alice", "company"},
		{"alice(contractor)", "alice", "contractor"},
		{"bob", "bob", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotShort, gotDomain := parseShareSegment(tt.input)
			if gotShort != tt.wantShort || gotDomain != tt.wantDomain {
				t.Errorf("parseShareSegment(%q) = (%q, %q), want (%q, %q)", tt.input, gotShort, gotDomain, tt.wantShort, tt.wantDomain)
			}
		})
	}
}

func TestLoginShortName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"joe@example.com", "joe"},
		{"joe", "joe"},
		{"alice@foo.bar.com", "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := LoginShortName(tt.input)
			if got != tt.want {
				t.Errorf("LoginShortName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchesGroup(t *testing.T) {
	tests := []struct {
		shareName string
		groups    []string
		want      bool
	}{
		{"eng", []string{"group:eng"}, true},
		{"eng", []string{"eng@example.com"}, true},
		{"eng", []string{"group:design", "group:eng"}, true},
		{"eng", []string{"group:design"}, false},
		{"eng", []string{}, false},
		{"design", []string{"engineering@example.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.shareName, func(t *testing.T) {
			got := matchesGroup(tt.shareName, tt.groups)
			if got != tt.want {
				t.Errorf("matchesGroup(%q, %v) = %v, want %v", tt.shareName, tt.groups, got, tt.want)
			}
		})
	}
}

func TestGroupShortName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"group:eng", "eng"},
		{"eng@example.com", "eng"},
		{"eng", "eng"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := GroupShortName(tt.input)
			if got != tt.want {
				t.Errorf("GroupShortName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterPermissionsByIdentity(t *testing.T) {
	shares := views.SliceOfViews([]*Share{
		{Name: "joe+rhea"},
		{Name: "docs"},
		{Name: "eng", IsGroup: true},
		{Name: "alice+bob"},
	})

	t.Run("multi-user share access", func(t *testing.T) {
		perms := Permissions{
			"*": PermissionReadWrite,
		}
		filtered := FilterPermissionsByIdentity(perms, "joe@example.com", nil, shares)
		// joe can access joe+rhea and docs, but not eng (group) or alice+bob
		if filtered.For("joe+rhea") != PermissionReadWrite {
			t.Error("joe should access joe+rhea")
		}
		if filtered.For("docs") != PermissionReadWrite {
			t.Error("joe should access docs")
		}
		if filtered.For("eng") != PermissionNone {
			t.Error("joe should not access eng (not in group)")
		}
		if filtered.For("alice+bob") != PermissionNone {
			t.Error("joe should not access alice+bob")
		}
	})

	t.Run("group share access", func(t *testing.T) {
		perms := Permissions{
			"*": PermissionReadOnly,
		}
		filtered := FilterPermissionsByIdentity(perms, "joe@example.com", []string{"group:eng"}, shares)
		if filtered.For("eng") != PermissionReadOnly {
			t.Error("joe in group:eng should access eng share")
		}
	})

	t.Run("specific share permission without wildcard", func(t *testing.T) {
		perms := Permissions{
			"joe+rhea": PermissionReadWrite,
			"alice+bob": PermissionReadOnly,
		}
		filtered := FilterPermissionsByIdentity(perms, "joe@example.com", nil, shares)
		if filtered.For("joe+rhea") != PermissionReadWrite {
			t.Error("joe should have rw to joe+rhea")
		}
		if filtered.For("alice+bob") != PermissionNone {
			t.Error("joe should not access alice+bob")
		}
	})

	t.Run("no restricted shares means no filtering", func(t *testing.T) {
		perms := Permissions{
			"*": PermissionReadWrite,
		}
		unrestricted := views.SliceOfViews([]*Share{
			{Name: "docs"},
			{Name: "photos"},
		})
		filtered := FilterPermissionsByIdentity(perms, "joe@example.com", nil, unrestricted)
		if filtered.For("docs") != PermissionReadWrite {
			t.Error("wildcard should pass through with no restricted shares")
		}
	})

	t.Run("empty shares means no filtering", func(t *testing.T) {
		perms := Permissions{
			"*": PermissionReadWrite,
		}
		empty := views.SliceOfViews([]*Share{})
		filtered := FilterPermissionsByIdentity(perms, "joe@example.com", nil, empty)
		if filtered.For("anything") != PermissionReadWrite {
			t.Error("wildcard should pass through with empty shares")
		}
	})

	t.Run("name(domain) share access", func(t *testing.T) {
		domainShares := views.SliceOfViews([]*Share{
			{Name: "alice(contractor)+bob"},
			{Name: "docs"},
		})
		perms := Permissions{
			"*": PermissionReadWrite,
		}
		// alice@contractor.io should access alice(contractor)+bob
		filtered := FilterPermissionsByIdentity(perms, "alice@contractor.io", nil, domainShares)
		if filtered.For("alice(contractor)+bob") != PermissionReadWrite {
			t.Error("alice@contractor.io should access alice(contractor)+bob")
		}
		// alice@example.com should NOT access alice(contractor)+bob
		filtered = FilterPermissionsByIdentity(perms, "alice@example.com", nil, domainShares)
		if filtered.For("alice(contractor)+bob") != PermissionNone {
			t.Error("alice@example.com should not access alice(contractor)+bob")
		}
		// bob@example.com should access alice(contractor)+bob
		filtered = FilterPermissionsByIdentity(perms, "bob@example.com", nil, domainShares)
		if filtered.For("alice(contractor)+bob") != PermissionReadWrite {
			t.Error("bob@example.com should access alice(contractor)+bob")
		}
	})
}
