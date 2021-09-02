// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import (
	"runtime"
	"testing"
)

func TestCurrentFileDescriptors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %v", runtime.GOOS)
	}
	if n := CurrentFDs(); n < 3 {
		t.Errorf("got %v; want >= 3", n)
	} else {
		t.Logf("got %v", n)
	}
}

func BenchmarkCurrentFileDescriptors(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = CurrentFDs()
	}
}
