// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"sync"

	"tailscale.com/types/logger"
)

// LinkChangeLogLimiter returns a new [logger.Logf] that logs each unique
// format string to the underlying logger only once per major LinkChange event.
//
// The returned function should be called when the logger is no longer needed,
// to release resources from the Monitor.
func LinkChangeLogLimiter(logf logger.Logf, nm *Monitor) (_ logger.Logf, unregister func()) {
	var formatSeen sync.Map // map[string]bool
	unregister = nm.RegisterChangeCallback(func(cd *ChangeDelta) {
		// If we're in a major change or a time jump, clear the seen map.
		if cd.Major || cd.TimeJumped {
			formatSeen.Clear()
		}
	})

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
	}, unregister
}
