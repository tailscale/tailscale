// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tailscale_go && (darwin || ios || android || ts_enable_sockstats)

package sockstats

import (
	"testing"
	"time"
)

type testTime struct {
	time.Time
}

func (t *testTime) now() time.Time {
	return t.Time
}

func (t *testTime) Add(d time.Duration) {
	t.Time = t.Time.Add(d)
}

func TestRadioMonitor(t *testing.T) {
	tests := []struct {
		name     string
		activity func(*testTime, *radioMonitor)
		want     int64
	}{
		{
			"no activity",
			func(_ *testTime, _ *radioMonitor) {},
			0,
		},
		{
			"active less than init stall period",
			func(tt *testTime, rm *radioMonitor) {
				rm.active()
				tt.Add(1 * time.Second)
			},
			0, // radio on, but not long enough to report data
		},
		{
			"active, 10 sec idle",
			func(tt *testTime, rm *radioMonitor) {
				rm.active()
				tt.Add(9 * time.Second)
			},
			50, // radio on 5 seconds of 10 seconds
		},
		{
			"active, spanning three seconds",
			func(tt *testTime, rm *radioMonitor) {
				rm.active()
				tt.Add(2100 * time.Millisecond)
				rm.active()
			},
			100, // radio on for 3 seconds
		},
		{
			"400 iterations: 2 sec active, 1 min idle",
			func(tt *testTime, rm *radioMonitor) {
				// 400 iterations to ensure values loop back around rm.usage array
				for range 400 {
					rm.active()
					tt.Add(1 * time.Second)
					rm.active()
					tt.Add(59 * time.Second)
				}
			},
			10, // radio on 6 seconds of every minute
		},
		{
			"activity at end of time window",
			func(tt *testTime, rm *radioMonitor) {
				tt.Add(3 * time.Second)
				rm.active()
			},
			25,
		},
	}

	oldStallPeriod := initStallPeriod
	initStallPeriod = 3
	t.Cleanup(func() { initStallPeriod = oldStallPeriod })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm := &testTime{time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)}
			rm := &radioMonitor{
				startTime: tm.Time.Unix(),
				now:       tm.now,
			}
			tt.activity(tm, rm)
			got := rm.radioHighPercent()
			if got != tt.want {
				t.Errorf("got radioOnPercent %d, want %d", got, tt.want)
			}
		})
	}
}
