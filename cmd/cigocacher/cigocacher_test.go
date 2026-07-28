// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"
	"time"
)

func TestAsyncPutTimeout(t *testing.T) {
	for size, expected := range map[int64]time.Duration{
		0:            5 * time.Second,
		10:           5 * time.Second,
		10 * 1 << 20: 5 * time.Second,
		20 * 1 << 20: 10 * time.Second,
		40 * 1 << 20: 20 * time.Second,
		60 * 1 << 20: 30 * time.Second,
		10 * 1 << 30: 30 * time.Second,
	} {
		if actual := asyncPutTimeout(size); actual != expected {
			t.Errorf("for size %d, expected %v, but got %v", size, expected, actual)
		}
	}
}
