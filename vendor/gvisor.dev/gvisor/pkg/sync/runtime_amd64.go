// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && go1.8 && !go1.19 && !goexperiment.staticlockranking
// +build amd64,go1.8,!go1.19,!goexperiment.staticlockranking

package sync

import (
	"sync/atomic"
)

const supportsWakeSuppression = true

// addrOfSpinning returns the address of runtime.sched.nmspinning.
func addrOfSpinning() *int32

// nmspinning caches addrOfSpinning.
var nmspinning = addrOfSpinning()

func preGoReadyWakeSuppression() {
	atomic.AddInt32(nmspinning, 1)
}

func postGoReadyWakeSuppression() {
	atomic.AddInt32(nmspinning, -1)
}
