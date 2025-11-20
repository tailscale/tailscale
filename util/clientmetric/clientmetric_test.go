// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package clientmetric

import (
	"expvar"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
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

func TestDisableDeltas(t *testing.T) {
	clearMetrics()

	c := NewCounter("foo")
	c.DisableDeltas()
	c.Set(123)

	if got, want := EncodeLogTailMetricsDelta(), "N06fooS02f601"; got != want {
		t.Errorf("first = %q; want %q", got, want)
	}

	c.Set(456)
	advanceTime()
	if got, want := EncodeLogTailMetricsDelta(), "S029007"; got != want {
		t.Errorf("second = %q; want %q", got, want)
	}
}

func TestWithFunc(t *testing.T) {
	clearMetrics()

	v := int64(123)
	NewCounterFunc("foo", func() int64 { return v })

	if got, want := EncodeLogTailMetricsDelta(), "N06fooS02f601"; got != want {
		t.Errorf("first = %q; want %q", got, want)
	}

	v = 456
	advanceTime()
	if got, want := EncodeLogTailMetricsDelta(), "I029a05"; got != want {
		t.Errorf("second = %q; want %q", got, want)
	}
}

func TestAggregateCounter(t *testing.T) {
	clearMetrics()

	c := qt.New(t)

	expv1 := &expvar.Int{}
	expv2 := &expvar.Int{}
	expv3 := &expvar.Int{}

	aggCounter := NewAggregateCounter("agg_counter")

	aggCounter.Register(expv1)
	c.Assert(aggCounter.Value(), qt.Equals, int64(0))

	expv1.Add(1)
	c.Assert(aggCounter.Value(), qt.Equals, int64(1))

	aggCounter.Register(expv2)
	c.Assert(aggCounter.Value(), qt.Equals, int64(1))

	expv1.Add(1)
	expv2.Add(1)
	c.Assert(aggCounter.Value(), qt.Equals, int64(3))

	// Adding a new expvar should not change the value
	// and any value the counter already had is reset
	expv3.Set(5)
	aggCounter.Register(expv3)
	c.Assert(aggCounter.Value(), qt.Equals, int64(3))

	// Registering the same expvar multiple times should not change the value
	aggCounter.Register(expv3)
	c.Assert(aggCounter.Value(), qt.Equals, int64(3))

	aggCounter.UnregisterAll()
	c.Assert(aggCounter.Value(), qt.Equals, int64(0))

	// Start over
	expv3.Set(5)
	aggCounter.Register(expv3)
	c.Assert(aggCounter.Value(), qt.Equals, int64(0))

	expv3.Set(5)
	c.Assert(aggCounter.Value(), qt.Equals, int64(5))
}
