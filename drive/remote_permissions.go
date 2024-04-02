// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package drive

import (
	"encoding/json"
	"fmt"
)

type Permission uint8

const (
	PermissionNone Permission = iota
	PermissionReadOnly
	PermissionReadWrite
)

const (
	accessReadOnly  = "ro"
	accessReadWrite = "rw"

	wildcardShare = "*"
)

// Permissions represents the set of permissions for a given principal to a
// set of shares.
type Permissions map[string]Permission

type grant struct {
	Shares []string
	Access string
}

// ParsePermissions builds a Permissions map from a lis of raw grants.
func ParsePermissions(rawGrants [][]byte) (Permissions, error) {
	permissions := make(Permissions)
	for _, rawGrant := range rawGrants {
		var g grant
		err := json.Unmarshal(rawGrant, &g)
		if err != nil {
			return nil, fmt.Errorf("unmarshal raw grants: %v", err)
		}
		for _, share := range g.Shares {
			existingPermission := permissions[share]
			permission := PermissionReadOnly
			if g.Access == accessReadWrite {
				permission = PermissionReadWrite
			}
			if permission > existingPermission {
				permissions[share] = permission
			}
		}
	}
	return permissions, nil
}

func (p Permissions) For(share string) Permission {
	specific := p[share]
	wildcard := p[wildcardShare]
	if specific > wildcard {
		return specific
	}
	return wildcard
}
