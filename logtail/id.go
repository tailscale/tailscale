// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import "tailscale.com/types/logid"

// Deprecated: Use "tailscale.com/types/logid".PrivateID instead.
type PrivateID = logid.PrivateID

// Deprecated: Use "tailscale.com/types/logid".NewPrivateID instead.
func NewPrivateID() (PrivateID, error) {
	return logid.NewPrivateID()
}

// Deprecated: Use "tailscale.com/types/logid".ParsePrivateID instead.
func ParsePrivateID(s string) (PrivateID, error) {
	return logid.ParsePrivateID(s)
}

// Deprecated: Use "tailscale.com/types/logid".PublicID instead.
type PublicID = logid.PublicID

// Deprecated: Use "tailscale.com/types/logid".ParsePublicID instead.
func ParsePublicID(s string) (PublicID, error) {
	return logid.ParsePublicID(s)
}
