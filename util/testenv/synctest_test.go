// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testenv_test

import (
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/util/testenv"
)

func TestInSynctestBubble(t *testing.T) {
	if testenv.InSynctestBubble() {
		t.Error("InSynctestBubble = true outside a bubble")
	}
	synctest.Test(t, func(t *testing.T) {
		if !testenv.InSynctestBubble() {
			t.Error("InSynctestBubble = false inside a bubble")
		}
		// Detection must not depend on the bubble's fake clock still
		// being near its 2000-01-01 start.
		time.Sleep(100 * 365 * 24 * time.Hour)
		if !testenv.InSynctestBubble() {
			t.Error("InSynctestBubble = false inside a bubble after advancing the fake clock")
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if !testenv.InSynctestBubble() {
				t.Error("InSynctestBubble = false in a goroutine started inside a bubble")
			}
		}()
		<-done
	})
	if testenv.InSynctestBubble() {
		t.Error("InSynctestBubble = true after bubble exited")
	}
}

func BenchmarkInSynctestBubble(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if testenv.InSynctestBubble() {
			b.Fatal("unexpectedly in bubble")
		}
	}
}
