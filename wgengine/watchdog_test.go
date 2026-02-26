// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package wgengine

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
)

func TestWatchdog(t *testing.T) {
	t.Parallel()

	var maxWaitMultiple time.Duration = 1
	if runtime.GOOS == "darwin" {
		// Work around slow close syscalls on Big Sur with content filter Network Extensions installed.
		// See https://github.com/tailscale/tailscale/issues/1598.
		maxWaitMultiple = 15
	}

	t.Run("default watchdog does not fire", func(t *testing.T) {
		t.Parallel()
		bus := eventbustest.NewBus(t)
		ht := health.NewTracker(bus)
		reg := new(usermetric.Registry)
		e, err := NewFakeUserspaceEngine(t.Logf, 0, ht, reg, bus)
		if err != nil {
			t.Fatal(err)
		}

		e = NewWatchdog(e)
		e.(*watchdogEngine).maxWait = maxWaitMultiple * 150 * time.Millisecond
		e.(*watchdogEngine).logf = t.Logf
		e.(*watchdogEngine).fatalf = t.Fatalf

		e.RequestStatus()
		e.RequestStatus()
		e.RequestStatus()
		e.Close()
	})
}

func TestWatchdogMetrics(t *testing.T) {
	tests := []struct {
		name       string
		events     []watchdogEvent
		wantCounts map[watchdogEvent]int64
	}{
		{
			name:   "single event types",
			events: []watchdogEvent{RequestStatus, PeerForIPEvent, Ping},
			wantCounts: map[watchdogEvent]int64{
				RequestStatus:  1,
				PeerForIPEvent: 1,
				Ping:           1,
			},
		},
		{
			name:   "repeated events",
			events: []watchdogEvent{RequestStatus, RequestStatus, Ping, RequestStatus},
			wantCounts: map[watchdogEvent]int64{
				RequestStatus: 3,
				Ping:          1,
			},
		},
	}

	// For swallowing fatalf calls and stack traces
	logf := func(format string, args ...any) {}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearMetrics(t)
			bus := eventbustest.NewBus(t)
			ht := health.NewTracker(bus)
			reg := new(usermetric.Registry)
			e, err := NewFakeUserspaceEngine(logf, 0, ht, reg, bus)
			if err != nil {
				t.Fatal(err)
			}
			e = NewWatchdog(e)
			w := e.(*watchdogEngine)
			w.maxWait = 1 * time.Microsecond
			w.logf = logf
			w.fatalf = logf

			var wg sync.WaitGroup
			wg.Add(len(tt.events))

			for _, ev := range tt.events {
				blocked := make(chan struct{})
				w.watchdog(ev, func() {
					defer wg.Done()
					<-blocked
				})
				close(blocked)
			}
			wg.Wait()

			// Check individual event counts
			for ev, want := range tt.wantCounts {
				m, ok := watchdogMetrics[ev]
				if !ok {
					t.Fatalf("no metric found for event %q", ev)
				}
				got := m.Value()
				if got != want {
					t.Errorf("got %d metric events for %q, want %d", got, ev, want)
				}
			}

			// Check total count for Any
			m, ok := watchdogMetrics[Any]
			if !ok {
				t.Fatalf("no Any metric found")
			}
			got := m.Value()
			if got != int64(len(tt.events)) {
				t.Errorf("got %d metric events for Any, want %d", got, len(tt.events))
			}
		})
	}
}

func clearMetrics(t *testing.T) {
	t.Helper()
	if watchdogMetrics == nil {
		return
	}
	for _, m := range watchdogMetrics {
		m.Set(0)
	}
}
