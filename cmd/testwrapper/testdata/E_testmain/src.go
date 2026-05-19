// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testmain

import (
	"sync"
	"testing"
)

var counter int

func TestPass(t *testing.T) {
}

func TestMain(m *testing.M) {
	code := m.Run()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); counter++ }()
	go func() { defer wg.Done(); counter++ }()
	wg.Wait()
	_ = code
}
