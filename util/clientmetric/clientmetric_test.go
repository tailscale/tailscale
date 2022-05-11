// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientmetric

import (
	"testing"
	"time"
)

func TestDeltaEncBuf(t *testing.T) {
	var enc deltaEncBuf
	enc.writeName("one_one", TypeCounter)
	enc.writeValue(1, 1)
	enc.writeName("two_zero", TypeGauge)
	enc.writeValue(2, 0)

	enc.writeDelta(1, 63)
	enc.writeDelta(2, 64)
	enc.writeDelta(1, -65)
	enc.writeDelta(2, -64)

	got := enc.buf.String()
	const want = "N0eone_oneS0202N1cgauge_two_zeroS0400I027eI048001I028101I047f"
	if got != want {
		t.Errorf("error\n got %q\nwant %q\n", got, want)
	}
}

func clearMetrics() {
	mu.Lock()
	defer mu.Unlock()
	metrics = map[string]*Metric{}
	numWireID = 0
	lastDelta = time.Time{}
	sorted = nil
	lastLogVal = nil
	unsorted = nil
}

func advanceTime() {
	mu.Lock()
	defer mu.Unlock()
	lastDelta = time.Time{}
}

func TestEncodeLogTailMetricsDelta(t *testing.T) {
	clearMetrics()

	c1 := NewCounter("foo")
	c2 := NewGauge("bar")
	c1.Add(123)
	if got, want := EncodeLogTailMetricsDelta(), "N06fooS02f601"; got != want {
		t.Errorf("first = %q; want %q", got, want)
	}

	c2.Add(456)
	advanceTime()
	if got, want := EncodeLogTailMetricsDelta(), "N12gauge_barS049007"; got != want {
		t.Errorf("second = %q; want %q", got, want)
	}

	advanceTime()
	if got, want := EncodeLogTailMetricsDelta(), ""; got != want {
		t.Errorf("with no changes = %q; want %q", got, want)
	}

	c1.Add(1)
	c2.Add(2)
	advanceTime()
	if got, want := EncodeLogTailMetricsDelta(), "I0202I0404"; got != want {
		t.Errorf("with increments = %q; want %q", got, want)
	}
}
