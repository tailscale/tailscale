// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package rate

import (
	"flag"
	"math"
	"reflect"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tstime/mono"
	"tailscale.com/util/must"
)

const (
	min  = mono.Time(time.Minute)
	sec  = mono.Time(time.Second)
	msec = mono.Time(time.Millisecond)
	usec = mono.Time(time.Microsecond)
	nsec = mono.Time(time.Nanosecond)

	val = 1.0e6
)

var longNumericalStabilityTest = flag.Bool("long-numerical-stability-test", false, "")

func TestValue(t *testing.T) {
	// When performing many small calculations, the accuracy of the
	// result can drift due to accumulated errors in the calculation.
	// Verify that the result is correct even with many small updates.
	// See https://en.wikipedia.org/wiki/Numerical_stability.
	t.Run("NumericalStability", func(t *testing.T) {
		step := usec
		if *longNumericalStabilityTest {
			step = nsec
		}
		numStep := int(sec / step)

		c := qt.New(t)
		var v Value
		var now mono.Time
		for range numStep {
			v.addNow(now, float64(step))
			now += step
		}
		c.Assert(v.rateNow(now), qt.CmpEquals(cmpopts.EquateApprox(1e-6, 0)), 1e9/2)
	})

	halfLives := []struct {
		name   string
		period time.Duration
	}{
		{"½s", time.Second / 2},
		{"1s", time.Second},
		{"2s", 2 * time.Second},
	}
	for _, halfLife := range halfLives {
		t.Run(halfLife.name+"/SpikeDecay", func(t *testing.T) {
			testValueSpikeDecay(t, halfLife.period, false)
		})
		t.Run(halfLife.name+"/SpikeDecayAddZero", func(t *testing.T) {
			testValueSpikeDecay(t, halfLife.period, true)
		})
		t.Run(halfLife.name+"/HighThenLow", func(t *testing.T) {
			testValueHighThenLow(t, halfLife.period)
		})
		t.Run(halfLife.name+"/LowFrequency", func(t *testing.T) {
			testLowFrequency(t, halfLife.period)
		})
	}
}

// testValueSpikeDecay starts with a target rate and ensure that it
// exponentially decays according to the half-life formula.
func testValueSpikeDecay(t *testing.T, halfLife time.Duration, addZero bool) {
	c := qt.New(t)
	v := Value{HalfLife: halfLife}
	v.addNow(0, val*v.normalizedIntegral())

	var now mono.Time
	var prevRate float64
	step := 100 * msec
	wantHalfRate := float64(val)
	for now < 10*sec {
		// Adding zero for every time-step will repeatedly trigger the
		// computation to decay the value, which may cause the result
		// to become more numerically unstable.
		if addZero {
			v.addNow(now, 0)
		}
		currRate := v.rateNow(now)
		t.Logf("%0.1fs:\t%0.3f", time.Duration(now).Seconds(), currRate)

		// At every multiple of a half-life period,
		// the current rate should be half the value of what
		// it was at the last half-life period.
		if time.Duration(now)%halfLife == 0 {
			c.Assert(currRate, qt.CmpEquals(cmpopts.EquateApprox(1e-12, 0)), wantHalfRate)
			wantHalfRate = currRate / 2
		}

		// Without any newly added events,
		// the rate should be decaying over time.
		if now > 0 && prevRate < currRate {
			t.Errorf("%v: rate is not decaying: %0.1f < %0.1f", time.Duration(now), prevRate, currRate)
		}
		if currRate < 0 {
			t.Errorf("%v: rate too low: %0.1f < %0.1f", time.Duration(now), currRate, 0.0)
		}

		prevRate = currRate
		now += step
	}
}

// testValueHighThenLow targets a steady-state rate that is high,
// then switches to a target steady-state rate that is low.
func testValueHighThenLow(t *testing.T, halfLife time.Duration) {
	c := qt.New(t)
	v := Value{HalfLife: halfLife}

	var now mono.Time
	var prevRate float64
	var wantRate float64
	const step = 10 * msec
	const stepsPerSecond = int(sec / step)

	// Target a higher steady-state rate.
	wantRate = 2 * val
	wantHalfRate := float64(0.0)
	eventsPerStep := wantRate / float64(stepsPerSecond)
	for now < 10*sec {
		currRate := v.rateNow(now)
		v.addNow(now, eventsPerStep)
		t.Logf("%0.1fs:\t%0.3f", time.Duration(now).Seconds(), currRate)

		// At every multiple of a half-life period,
		// the current rate should be half-way more towards
		// the target rate relative to before.
		if time.Duration(now)%halfLife == 0 {
			c.Assert(currRate, qt.CmpEquals(cmpopts.EquateApprox(0.1, 0)), wantHalfRate)
			wantHalfRate += (wantRate - currRate) / 2
		}

		// Rate should approach wantRate from below,
		// but never exceed it.
		if now > 0 && prevRate > currRate {
			t.Errorf("%v: rate is not growing: %0.1f > %0.1f", time.Duration(now), prevRate, currRate)
		}
		if currRate > 1.01*wantRate {
			t.Errorf("%v: rate too high: %0.1f > %0.1f", time.Duration(now), currRate, wantRate)
		}

		prevRate = currRate
		now += step
	}
	c.Assert(prevRate, qt.CmpEquals(cmpopts.EquateApprox(0.05, 0)), wantRate)

	// Target a lower steady-state rate.
	wantRate = val / 3
	wantHalfRate = prevRate
	eventsPerStep = wantRate / float64(stepsPerSecond)
	for now < 20*sec {
		currRate := v.rateNow(now)
		v.addNow(now, eventsPerStep)
		t.Logf("%0.1fs:\t%0.3f", time.Duration(now).Seconds(), currRate)

		// At every multiple of a half-life period,
		// the current rate should be half-way more towards
		// the target rate relative to before.
		if time.Duration(now)%halfLife == 0 {
			c.Assert(currRate, qt.CmpEquals(cmpopts.EquateApprox(0.1, 0)), wantHalfRate)
			wantHalfRate += (wantRate - currRate) / 2
		}

		// Rate should approach wantRate from above,
		// but never exceed it.
		if now > 10*sec && prevRate < currRate {
			t.Errorf("%v: rate is not decaying: %0.1f < %0.1f", time.Duration(now), prevRate, currRate)
		}
		if currRate < 0.99*wantRate {
			t.Errorf("%v: rate too low: %0.1f < %0.1f", time.Duration(now), currRate, wantRate)
		}

		prevRate = currRate
		now += step
	}
	c.Assert(prevRate, qt.CmpEquals(cmpopts.EquateApprox(0.15, 0)), wantRate)
}

// testLowFrequency fires an event at a frequency much slower than
// the specified half-life period. While the average rate over time
// should be accurate, the standard deviation gets worse.
func testLowFrequency(t *testing.T, halfLife time.Duration) {
	v := Value{HalfLife: halfLife}

	var now mono.Time
	var rates []float64
	for now < 20*min {
		if now%(10*sec) == 0 {
			v.addNow(now, 1) // 1 event every 10 seconds
		}
		now += 50 * msec
		rates = append(rates, v.rateNow(now))
		now += 50 * msec
	}

	mean, stddev := stats(rates)
	c := qt.New(t)
	c.Assert(mean, qt.CmpEquals(cmpopts.EquateApprox(0.001, 0)), 0.1)
	t.Logf("mean:%v stddev:%v", mean, stddev)
}

func stats(fs []float64) (mean, stddev float64) {
	for _, rate := range fs {
		mean += rate
	}
	mean /= float64(len(fs))
	for _, rate := range fs {
		stddev += (rate - mean) * (rate - mean)
	}
	stddev = math.Sqrt(stddev / float64(len(fs)))
	return mean, stddev
}

// BenchmarkValue benchmarks the cost of Value.Add,
// which is called often and makes extensive use of floating-point math.
func BenchmarkValue(b *testing.B) {
	b.ReportAllocs()
	v := Value{HalfLife: time.Second}
	for range b.N {
		v.Add(1)
	}
}

func TestValueMarshal(t *testing.T) {
	now := mono.Now()
	tests := []struct {
		val *Value
		str string
	}{
		{val: &Value{}, str: `{}`},
		{val: &Value{HalfLife: 5 * time.Minute}, str: `{"halfLife":"` + (5 * time.Minute).String() + `"}`},
		{val: &Value{value: 12345, updated: now}, str: `{"value":12345,"updated":` + string(must.Get(now.MarshalJSON())) + `}`},
	}
	for _, tt := range tests {
		str := string(must.Get(tt.val.MarshalJSON()))
		if str != tt.str {
			t.Errorf("string mismatch: got %v, want %v", str, tt.str)
		}
		var val Value
		must.Do(val.UnmarshalJSON([]byte(str)))
		if !reflect.DeepEqual(&val, tt.val) {
			t.Errorf("value mismatch: %+v, want %+v", &val, tt.val)
		}
	}
}
