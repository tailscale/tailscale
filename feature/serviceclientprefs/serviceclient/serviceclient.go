// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package serviceclient holds the types for the desktop clients' saved service launch preferences.
// They're shared by the serviceclientprefs feature and the LocalAPI client.
package serviceclient

import (
	"time"
)

// Prefs maps a service key to the user's saved preferences for that service.
// Keys are "<serviceName>:<port>" where serviceName is a [tailcfg.ServiceName]
// (e.g. key "svc:my-db:5432" for service "svc:my-db" on port 5432).
type Prefs map[string]Pref

// Pref captures the saved preferences for one service.
type Pref struct {
	// Client is the saved client identifier the user picked in the last service launch,
	// for example, terminal/putty/iterm2/... for SSH, and dbeaver/psql/mycli/... for
	// database. Empty means no client has been saved for this service.
	Client string `json:",omitzero"`

	// Username is the saved login name for SSH and future services that require username.
	// Empty means none saved.
	Username string `json:",omitzero"`

	// DatabaseName is the saved DB name (database service types). Empty means none saved.
	DatabaseName string `json:",omitzero"`

	// LastUsed is when this service was last launched. Zero means never.
	// When the macOS and Windows apps generate a "recently used" list, they sort by
	// LastUsed descending.
	LastUsed time.Time `json:",omitzero"`
}
