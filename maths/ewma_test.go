// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package maths

import (
	"slices"
	"testing"
	"time"
)

// some real world latency samples.
var (
	latencyHistory1 = []int{
		14, 12, 15, 6, 19, 12, 13, 13, 13, 16, 17, 11, 17, 11, 14, 15, 14, 15,
		16, 16, 17, 14, 12, 16, 18, 14, 14, 11, 15, 15, 25, 11, 15, 14, 12, 15,
		13, 12, 13, 15, 11, 13, 15, 14, 14, 15, 12, 15, 18, 12, 15, 22, 12, 13,
		10, 14, 16, 15, 16, 11, 14, 17, 18, 20, 16, 11, 16, 14, 5, 15, 17, 12,
		15, 11, 15, 20, 12, 17, 12, 17, 15, 12, 12, 11, 14, 15, 11, 20, 14, 13,
		11, 12, 13, 13, 11, 13, 11, 15, 13, 13, 14, 12, 11, 12, 12, 14, 11, 13,
		12, 12, 12, 19, 14, 13, 13, 14, 11, 12, 10, 11, 15, 12, 14, 11, 11, 14,
		14, 12, 12, 11, 14, 12, 11, 12, 14, 11, 12, 15, 12, 14, 12, 12, 21, 16,
		21, 12, 16, 9, 11, 16, 14, 13, 14, 12, 13, 16,
	}
	latencyHistory2 = []int{
		18, 20, 21, 21, 20, 23, 18, 18, 20, 21, 20, 19, 22, 18, 20, 20, 19, 21,
		21, 22, 22, 19, 18, 22, 22, 19, 20, 17, 16, 11, 25, 16, 18, 21, 17, 22,
		19, 18, 22, 21, 20, 18, 22, 17, 17, 20, 19, 10, 19, 16, 19, 25, 17, 18,
		15, 20, 21, 20, 23, 22, 22, 22, 19, 22, 22, 17, 22, 20, 20, 19, 21, 22,
		20, 19, 17, 22, 16, 16, 20, 22, 17, 19, 21, 16, 20, 22, 19, 21, 20, 19,
		13, 14, 23, 19, 16, 10, 19, 15, 15, 17, 16, 18, 14, 16, 18, 22, 20, 18,
		18, 21, 15, 19, 18, 19, 18, 20, 17, 19, 21, 19, 20, 19, 20, 20, 17, 14,
		17, 17, 18, 21, 20, 18, 18, 17, 16, 17, 17, 20, 22, 19, 20, 21, 21, 20,
		21, 24, 20, 18, 12, 17, 18, 17, 19, 19, 19,
	}
)

func TestEWMALatencyHistory(t *testing.T) {
	type result struct {
		t time.Time
		v float64
		s int
	}

	for _, latencyHistory := range [][]int{latencyHistory1, latencyHistory2} {
		startTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
		halfLife := 30.0

		ewma := NewEWMA(halfLife)

		var results []result
		sum := 0.0
		for i, latency := range latencyHistory {
			t := startTime.Add(time.Duration(i) * time.Second)
			ewma.Update(float64(latency), t)
			sum += float64(latency)

			results = append(results, result{t, ewma.Get(), latency})
		}
		mean := sum / float64(len(latencyHistory))
		min := float64(slices.Min(latencyHistory))
		max := float64(slices.Max(latencyHistory))

		t.Logf("EWMA Latency History (half-life: %.1f seconds):", halfLife)
		t.Logf("Mean latency: %.2f ms", mean)
		t.Logf("Range: [%.1f, %.1f]", min, max)

		t.Log("Samples: ")
		sparkline := []rune("▁▂▃▄▅▆▇█")
		var sampleLine []rune
		for _, r := range results {
			idx := int(((float64(r.s) - min) / (max - min)) * float64(len(sparkline)-1))
			if idx >= len(sparkline) {
				idx = len(sparkline) - 1
			}
			sampleLine = append(sampleLine, sparkline[idx])
		}
		t.Log(string(sampleLine))

		t.Log("EWMA:    ")
		var ewmaLine []rune
		for _, r := range results {
			idx := int(((r.v - min) / (max - min)) * float64(len(sparkline)-1))
			if idx >= len(sparkline) {
				idx = len(sparkline) - 1
			}
			ewmaLine = append(ewmaLine, sparkline[idx])
		}
		t.Log(string(ewmaLine))
		t.Log("")

		t.Logf("Time       | Sample | Value  | Value - Sample")
		t.Logf("")

		for _, result := range results {
			t.Logf("%10s | % 6d | % 5.2f | % 5.2f", result.t.Format("15:04:05"), result.s, result.v, result.v-float64(result.s))
		}

		// check that all results are greater than the min, and less than the max of the input,
		// and they're all close to the mean.
		for _, result := range results {
			if result.v < float64(min) || result.v > float64(max) {
				t.Errorf("result %f out of range [%f, %f]", result.v, min, max)
			}

			if result.v < mean*0.9 || result.v > mean*1.1 {
				t.Errorf("result %f not close to mean %f", result.v, mean)
			}
		}
	}
}

func TestHalfLife(t *testing.T) {
	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	ewma := NewEWMA(30.0)
	ewma.Update(10, start)
	ewma.Update(0, start.Add(30*time.Second))

	if ewma.Get() != 5 {
		t.Errorf("expected 5, got %f", ewma.Get())
	}

	ewma.Update(10, start.Add(60*time.Second))
	if ewma.Get() != 7.5 {
		t.Errorf("expected 7.5, got %f", ewma.Get())
	}

	ewma.Update(10, start.Add(90*time.Second))
	if ewma.Get() != 8.75 {
		t.Errorf("expected 8.75, got %f", ewma.Get())
	}
}

func TestZeroValue(t *testing.T) {
	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	var ewma EWMA
	ewma.Update(10, start)
	ewma.Update(0, start.Add(time.Second))

	if ewma.Get() != 5 {
		t.Errorf("expected 5, got %f", ewma.Get())
	}

	ewma.Update(10, start.Add(2*time.Second))
	if ewma.Get() != 7.5 {
		t.Errorf("expected 7.5, got %f", ewma.Get())
	}

	ewma.Update(10, start.Add(3*time.Second))
	if ewma.Get() != 8.75 {
		t.Errorf("expected 8.75, got %f", ewma.Get())
	}
}

func TestReset(t *testing.T) {
	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	ewma := NewEWMA(30.0)
	ewma.Update(10, start)
	ewma.Update(0, start.Add(30*time.Second))

	if ewma.Get() != 5 {
		t.Errorf("expected 5, got %f", ewma.Get())
	}

	ewma.Reset()

	if ewma.Get() != 0 {
		t.Errorf("expected 0, got %f", ewma.Get())
	}

	ewma.Update(10, start.Add(90*time.Second))
	if ewma.Get() != 10 {
		t.Errorf("expected 10, got %f", ewma.Get())
	}
}
