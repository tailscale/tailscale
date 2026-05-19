// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package inbody

import (
	"sync"
	"testing"
)

var counter int

func TestRace(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); counter++ }()
	go func() { defer wg.Done(); counter++ }()
	wg.Wait()
}
