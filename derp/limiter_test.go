// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"testing"
	"time"
)

func mb(mb uint64) uint64 {
	return mb * 1024 * 1024
}

func TestLimiterLoopGradual(t *testing.T) {
	// Make a limiter that tries to keep under 200Mb/s.
	limit := mb(200)
	start := time.Now()
	l := newLimiterLoop(limit, start)

	// Make sure the initial value is sane.
	// Lets imagine the egress is only like 1Mb/s.
	now := start.Add(time.Second)
	if v := uint64(l.tick(1024*1024, now)); v < mb(150) || v > limit {
		t.Errorf("initial value = %dMb/s, want 150 < value < limit", v/1024/1024)
	}

	// Tick through 10 minutes of low usage. Lets make sure the limit stays high.
	lowUsage := limit / 10
	for i := 0; i < 600; i++ {
		now = now.Add(time.Second)
		v := uint64(l.tick(lowUsage, now))

		if v < mb(150) {
			t.Errorf("[t=%0.f] limit too low for low usage: %d (expected >150)", now.Sub(start).Seconds(), v/1024/1024)
		}
	}

	// Lets tick through 60 seconds of steadily-increasing usage.
	for i := 0; i < 60; i++ {
		now = now.Add(time.Second)
		l.tick(uint64(i)*limit/60, now)
	}
	if v := uint64(l.tick(limit, now)); v > mb(100) || v < mb(1) {
		t.Errorf("[t=%0.f] limit = %dMb/s, want 1-100Mb/s", now.Sub(start).Seconds(), v/1024/1024)
	}
	// Lets imagine we are at limits for 10s. Does the limit drop pretty hard?
	for i := 0; i < 10; i++ {
		now = now.Add(time.Second)
		l.tick(limit, now)
	}
	if v := uint64(l.tick(limit, now)); v > mb(20) || v < mb(1) {
		t.Errorf("[t=%0.f] limit = %dMb/s, want 1-20Mb/s", now.Sub(start).Seconds(), v/1024/1024)
	}
}
