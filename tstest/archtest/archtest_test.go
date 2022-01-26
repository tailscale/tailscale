// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package archtest

import (
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// tests netstack's AlignedAtomicInt64.
func TestAlignedAtomicInt64(t *testing.T) {
	type T struct {
		A atomicbitops.AlignedAtomicInt64
		x int32
		B atomicbitops.AlignedAtomicInt64
	}

	t.Logf("I am %v/%v\n", runtime.GOOS, runtime.GOARCH)
	var x T
	x.A.Store(1)
	x.B.Store(2)
	if got, want := x.A.Load(), int64(1); got != want {
		t.Errorf("A = %v; want %v", got, want)
	}
	if got, want := x.B.Load(), int64(2); got != want {
		t.Errorf("A = %v; want %v", got, want)
	}
}
