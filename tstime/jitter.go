// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstime

import (
	"math/rand/v2"
	"time"
)

// RandomDurationBetween returns a random duration in range [min,max).
// If panics if max < min.
func RandomDurationBetween(min, max time.Duration) time.Duration {
	diff := max - min
	if diff == 0 {
		return min
	}
	return min + rand.N(max-min)
}
