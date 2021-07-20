// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mono

import (
	"testing"
	"time"
)

func TestNow(t *testing.T) {
	start := Now()
	time.Sleep(100 * time.Millisecond)
	if elapsed := Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("short sleep: %v elapsed, want min %v", elapsed, 100*time.Millisecond)
	}
}

func BenchmarkMonoNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Now()
	}
}

func BenchmarkTimeNow(b *testing.B) {
	for i := 0; i < b.N; i++ {
		time.Now()
	}
}
