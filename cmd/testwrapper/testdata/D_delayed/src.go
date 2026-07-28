// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package delayed

import (
	"sync"
	"testing"
	"time"
)

var counter int
var wg sync.WaitGroup
var trigger = make(chan struct{})

func TestA(t *testing.T) {
	wg.Add(2)
	go func() { defer wg.Done(); <-trigger; counter++ }()
	go func() { defer wg.Done(); <-trigger; counter++ }()
}

func TestSleep(t *testing.T) {
	close(trigger)
	// Sleep long enough that the goroutines race during this sleep,
	// but TestSleep itself doesn't write to counter.
	time.Sleep(50 * time.Millisecond)
	wg.Wait()
}
