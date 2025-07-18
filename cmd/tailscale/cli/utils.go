// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"time"

	"tailscale.com/ipn/ipnstate"
)

func CalculateLastSeenTime(ps *ipnstate.PeerStatus) string {
	var lastseen string
	if !ps.LastSeen.IsZero() {
		now := time.Now()
		duration := now.Sub(ps.LastSeen)
		// an edge case during testing showed "-1m ago"
		duration = max(duration, 0)

		switch {
		case duration < time.Hour:
			minutes := int(duration.Minutes())
			lastseen = fmt.Sprintf("%dm ago", minutes)
		case duration < 24*time.Hour:
			hours := int(duration.Hours())
			lastseen = fmt.Sprintf("%dh ago", hours)
		default:
			days := int(duration.Hours() / 24)
			lastseen = fmt.Sprintf("%dd ago", days)
		}
	}
	return lastseen
}
