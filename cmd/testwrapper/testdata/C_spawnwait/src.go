// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package spawnwait

import (
	"sync"
	"testing"
)

var counter int
var wg sync.WaitGroup

func TestSpawn(t *testing.T) {
	wg.Add(2)
	go func() { defer wg.Done(); counter++ }()
	go func() { defer wg.Done(); counter++ }()
}

func TestWait(t *testing.T) {
	wg.Wait()
}
