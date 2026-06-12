// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package parallel

import "testing"

var counter int

func TestParA(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		counter++
	}
}

func TestParB(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		counter++
	}
}
