// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"context"
	"sync"
	"time"

	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

const cooldownSeconds = 300

// LinkChangeLogLimiter returns a new [logger.Logf] that logs each unique
// format string to the underlying logger only once per major LinkChange event
// with a cooldownSeconds second cooldown.
//
// The logger stops tracking seen format strings when the provided context is
// done.
func LinkChangeLogLimiter(ctx context.Context, logf logger.Logf, nm *Monitor) logger.Logf {
	var formatLastSeen sync.Map // map[string]int64

	sub := eventbus.SubscribeFunc(nm.b, func(cd *ChangeDelta) {
		// Any link changes that are flagged as likely require a rebind are
		// interesting enough that we should log them.
		if cd.RebindLikelyRequired {
			formatLastSeen.Clear()
		}
	})
	context.AfterFunc(ctx, sub.Close)
	return func(format string, args ...any) {
		// get the current timestamp
		now := time.Now().Unix()
		lastSeen, ok := formatLastSeen.Load(format)
		if ok {
			// if we've seen this format string within the last cooldownSeconds, skip logging
			if now-lastSeen.(int64) < cooldownSeconds {
				return
			}
		}
		// update the last seen timestamp for this format string
		formatLastSeen.Store(format, now)

		logf(format, args...)
	}
}
