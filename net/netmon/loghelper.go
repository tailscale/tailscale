// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"context"
	"sync"

	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// LinkChangeLogLimiter returns a new [logger.Logf] that logs each unique
// format string to the underlying logger only once per major LinkChange event.
//
// The logger stops tracking seen format strings when the provided context is
// done.
func LinkChangeLogLimiter(ctx context.Context, logf logger.Logf, nm *Monitor) logger.Logf {
	var formatSeen sync.Map // map[string]bool
	sub := eventbus.SubscribeFunc(nm.b, func(cd ChangeDelta) {
		// If we're in a major change or a time jump, clear the seen map.
		if cd.Major || cd.TimeJumped {
			formatSeen.Clear()
		}
	})
	context.AfterFunc(ctx, sub.Close)
	return func(format string, args ...any) {
		// We only store 'true' in the map, so if it's present then it
		// means we've already logged this format string.
		_, loaded := formatSeen.LoadOrStore(format, true)
		if loaded {
			// TODO(andrew-d): we may still want to log this
			// message every N minutes (1x/hour?) even if it's been
			// seen, so that debugging doesn't require searching
			// back in the logs for an unbounded amount of time.
			//
			// See: https://github.com/tailscale/tailscale/issues/13145
			return
		}

		logf(format, args...)
	}
}
