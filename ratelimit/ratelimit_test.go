// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ratelimit

import (
	"testing"
	"time"
)

func TestBucket(t *testing.T) {
	b := Bucket{
		FillInterval: time.Second,
		Burst:        3,
	}
	expect := []int{3, 2, 1, 0, 0}
	for i, want := range expect {
		got := b.TryGet()
		if want != got {
			t.Errorf("#%d want=%d got=%d\n", i, want, got)
		}
	}
	b.tick()
	if want, got := 1, b.TryGet(); want != got {
		t.Errorf("after tick: want=%d got=%d\n", want, got)
	}
}
