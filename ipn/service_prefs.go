// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"maps"
	"time"
)

// ServicePrefs maps a service action key to the user's saved preferences for that action.
// Keys are formatted as "<serviceName>:<port>" (e.g. "svc:my-db:5432").
type ServicePrefs map[string]ServicePref

// ServicePref captures the saved preferences for one service action.
type ServicePref struct {
	// Client is the saved client identifier the user picked in the last service launch,
	// for example, terminal/putty/iterm2/... for SSH, and dbeaver/psql/mycli/... for
	// database. Empty means no client has been saved for this action.
	Client string

	// Username is the saved login name for SSH and future services that require username.
	// Empty means none saved.
	Username string

	// DatabaseName is the saved DB name (database service types). Empty means none saved.
	DatabaseName string

	// LastUsed is when this service action was last launched. Zero means never.
	// When the macOS and Windows apps generate a "recently used" list, they sort by
	// LastUsed descending.
	LastUsed time.Time
}

// Clone returns a shallow copy of this ServicePrefs, and since ServicePref is a value type,
// so the entries are independent of the source map it's cloning from.
func (sp ServicePrefs) Clone() ServicePrefs {
	if sp == nil {
		return nil
	}
	return maps.Clone(sp)
}
