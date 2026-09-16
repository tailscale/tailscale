// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"bytes"
	"io"
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

// TestSynctestBubbleIsolationStreaming verifies the same isolation property
// as TestSynctestBubbleIsolation for the streaming GetDecoder and
// GetStreamingEncoder APIs, whose pools are separate from the stateless
// coders'.
func TestSynctestBubbleIsolationStreaming(t *testing.T) {
	src := []byte("hello, hello, hello, world, world, world")

	synctest.Test(t, func(t *testing.T) {
		for range 10 {
			enc, putEnc := GetStreamingEncoder(FastestCompression)
			enc.Reset(&bytes.Buffer{})
			enc.Close()
			putEnc()

			dec, putDec := GetDecoder()
			if err := dec.Reset(bytes.NewReader(src)); err != nil {
				t.Fatal(err)
			}
			putDec()
		}
	})

	// A bubble-created streaming coder must never be reused outside the
	// bubble; prior to the nil-pool guard in GetStreamingEncoder's put
	// function, put panicked inside the bubble instead.
	for range 10 {
		var buf bytes.Buffer
		enc, putEnc := GetStreamingEncoder(FastestCompression)
		enc.Reset(&buf)
		if _, err := enc.Write(src); err != nil {
			t.Fatal(err)
		}
		if err := enc.Close(); err != nil {
			t.Fatal(err)
		}
		putEnc()

		dec, putDec := GetDecoder()
		if err := dec.Reset(bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatal(err)
		}
		out, err := io.ReadAll(dec)
		if err != nil {
			t.Fatal(err)
		}
		putDec()
		if !bytes.Equal(out, src) {
			t.Fatalf("roundtrip outside bubble = %q, want %q", out, src)
		}
	}
}
