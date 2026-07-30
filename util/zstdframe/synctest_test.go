// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"
)

// TestSynctestBubbleIsolation verifies that coders used within a
// testing/synctest bubble do not crash the process when zstdframe is
// subsequently used outside the bubble (or in another bubble).
//
// The zstd Encoder and Decoder types use channels internally, so a pooled
// coder that was created within a synctest bubble must never be reused
// outside of it: the runtime kills the process with "fatal error: receive
// on synctest channel from outside bubble".
func TestSynctestBubbleIsolation(t *testing.T) {
	src := []byte("hello, hello, hello, world, world, world")

	// Use the coder pools within a bubble several times to make it very
	// likely that a bubble-created coder would land in the package-level
	// pools if pooling were (incorrectly) enabled here.
	var frame []byte
	synctest.Test(t, func(t *testing.T) {
		for range 10 {
			frame = AppendEncode(nil, src)
			out, err := AppendDecode(nil, frame)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, src) {
				t.Fatalf("roundtrip inside bubble = %q, want %q", out, src)
			}
		}
		// Bubble detection must not depend on the fake clock still being
		// near its 2000-01-01 start, so advance it past the real
		// process start time and use the coders again.
		time.Sleep(100 * 365 * 24 * time.Hour)
		frame = AppendEncode(nil, src)
		if _, err := AppendDecode(nil, frame); err != nil {
			t.Fatal(err)
		}
	})

	// Prior to pooling being disabled in tests, this crashed the process
	// by reusing a pooled coder whose channels were created in the
	// now-exited bubble above.
	for range 10 {
		got := AppendEncode(nil, src)
		out, err := AppendDecode(nil, got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, src) {
			t.Fatalf("roundtrip outside bubble = %q, want %q", out, src)
		}
	}
}
