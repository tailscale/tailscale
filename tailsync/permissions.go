// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailsync

import (
	"encoding/json"
	"fmt"
)

// Permission represents the access level for a sync root.
type Permission uint8

const (
	PermissionNone Permission = iota
	PermissionReadOnly
	PermissionReadWrite
)

const (
	accessReadOnly  = "ro"
	accessReadWrite = "rw"
	wildcardRoot    = "*"
)

// Permissions maps root names to permission levels.
type Permissions map[string]Permission

type grant struct {
	Roots  []string `json:"roots"`
	Access string   `json:"access"`
}

// ParsePermissions builds a Permissions map from raw grant payloads.
func ParsePermissions(rawGrants [][]byte) (Permissions, error) {
	permissions := make(Permissions)
	for _, rawGrant := range rawGrants {
		var g grant
		err := json.Unmarshal(rawGrant, &g)
		if err != nil {
			return nil, fmt.Errorf("unmarshal raw grant %s: %v", rawGrant, err)
		}
		for _, root := range g.Roots {
			existing := permissions[root]
			permission := PermissionReadOnly
			if g.Access == accessReadWrite {
				permission = PermissionReadWrite
			}
			if permission > existing {
				permissions[root] = permission
			}
		}
	}
	return permissions, nil
}

// For returns the permission level for the given root name.
func (p Permissions) For(root string) Permission {
	specific := p[root]
	wildcard := p[wildcardRoot]
	if specific > wildcard {
		return specific
	}
	return wildcard
}
