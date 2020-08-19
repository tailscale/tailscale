// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// Parse a backward-compatible FilterRule used by control's wire format,
// producing the most current filter.Matches format.
// This is a wrapper to add logging
func (c *Direct) parsePacketFilter(pf []tailcfg.FilterRule) filter.Matches {
	mm, erracc := filter.MatchesFromFilterRules(pf)
	if erracc != nil {
		c.logf("parsePacketFilter: %s\n", erracc)
	}
	return mm
}
