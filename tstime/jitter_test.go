// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstime

import (
	"testing"
	"time"
)

func TestRandomDurationBetween(t *testing.T) {
	if got := RandomDurationBetween(1, 1); got != 1 {
		t.Errorf("between 1 and 1 = %v; want 1", int64(got))
	}
	const min = 1 * time.Second
	const max = 10 * time.Second
	for i := 0; i < 500; i++ {
		if got := RandomDurationBetween(min, max); got < min || got >= max {
			t.Fatalf("%v (%d) out of range", got, got)
		}
	}
}
