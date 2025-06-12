// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbustest

import (
	"fmt"
	"testing"
	"time"

	"tailscale.com/util/eventbus"
)

type EventFoo struct {
	Value int
}

type EventBar struct {
	Value string
}

type EventBaz struct {
	Value []float64
}

func TestExpect(t *testing.T) {
	tests := []struct {
		name      string
		numEvents int
		wantErr   bool
	}{
		{
			name:      "with no event",
			numEvents: 0,
			wantErr:   true,
		},
		{
			name:      "with event",
			numEvents: 1,
			wantErr:   false,
		},
		{
			name:      "with more events",
			numEvents: 10,
			wantErr:   false,
		},
	}

	bus := NewBus(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 1 * time.Millisecond

			client := bus.Client("testClient")
			updater := eventbus.Publish[EventFoo](client)

			for range tt.numEvents {
				updater.Publish(EventFoo{42})
			}

			if err := Expect[EventFoo](tw); (err != nil) != tt.wantErr {
				t.Errorf("Expect[EventFoo]: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectFunc(t *testing.T) {
	tests := []struct {
		name       string
		events     []int
		expectFunc func(event EventFoo) (bool, error)
		wantErr    bool
	}{
		{
			name:   "filter on event",
			events: []int{24, 42},
			expectFunc: func(event EventFoo) (bool, error) {
				if event.Value == 42 {
					return true, nil
				}
				return false, nil
			},
			wantErr: false,
		},
		{
			name:   "first event has to be func",
			events: []int{24, 42},
			expectFunc: func(event EventFoo) (bool, error) {
				if event.Value != 42 {
					return false, fmt.Errorf("expected 42, got %d", event.Value)
				}
				return false, nil
			},
			wantErr: true,
		},
		{
			name:   "no events",
			events: []int{},
			expectFunc: func(event EventFoo) (bool, error) {
				return true, nil
			},
			wantErr: true,
		},
	}

	bus := NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 1 * time.Millisecond

			client := bus.Client("testClient")
			updater := eventbus.Publish[EventFoo](client)

			for _, i := range tt.events {
				updater.Publish(EventFoo{i})
			}

			if err := ExpectFunc(tw, tt.expectFunc); (err != nil) != tt.wantErr {
				t.Errorf("ExpectFunc[EventFoo]: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectEvents(t *testing.T) {
	tests := []struct {
		name         string
		events       []any
		expectEvents []any
		wantErr      bool
	}{
		{
			name:         "No expectations",
			events:       []any{EventFoo{}},
			expectEvents: []any{},
			wantErr:      false,
		},
		{
			name:         "One event",
			events:       []any{EventFoo{}},
			expectEvents: []any{EventFoo{}},
			wantErr:      false,
		},
		{
			name:         "Two events",
			events:       []any{EventFoo{}, EventBar{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      false,
		},
		{
			name:         "Two expected events with another in the middle",
			events:       []any{EventFoo{}, EventBaz{}, EventBar{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      false,
		},
		{
			name:         "Missing event",
			events:       []any{EventFoo{}, EventBaz{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      true,
		},
	}

	bus := NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 1 * time.Millisecond

			client := bus.Client("testClient")
			updaterFoo := eventbus.Publish[EventFoo](client)
			updaterBar := eventbus.Publish[EventBar](client)
			updaterBaz := eventbus.Publish[EventBaz](client)

			for _, ev := range tt.events {
				switch ev.(type) {
				case EventFoo:
					evCast := ev.(EventFoo)
					updaterFoo.Publish(evCast)
				case EventBar:
					evCast := ev.(EventBar)
					updaterBar.Publish(evCast)
				case EventBaz:
					evCast := ev.(EventBaz)
					updaterBaz.Publish(evCast)
				}
			}

			if err := ExpectEvents(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectOnlyEvents(t *testing.T) {
	tests := []struct {
		name         string
		events       []any
		expectEvents []any
		wantErr      bool
	}{
		{
			name:         "No expectations",
			events:       []any{EventFoo{}},
			expectEvents: []any{},
			wantErr:      false,
		},
		{
			name:         "One event",
			events:       []any{EventFoo{}},
			expectEvents: []any{EventFoo{}},
			wantErr:      false,
		},
		{
			name:         "Two events",
			events:       []any{EventFoo{}, EventBar{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      false,
		},
		{
			name:         "Two expected events with another in the middle",
			events:       []any{EventFoo{}, EventBaz{}, EventBar{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      true,
		},
		{
			name:         "Wrong event",
			events:       []any{EventFoo{}, EventBaz{}},
			expectEvents: []any{EventFoo{}, EventBar{}},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := NewBus(t)
			tw := NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 1 * time.Millisecond

			client := bus.Client("testClient")
			updaterFoo := eventbus.Publish[EventFoo](client)
			updaterBar := eventbus.Publish[EventBar](client)
			updaterBaz := eventbus.Publish[EventBaz](client)

			for _, ev := range tt.events {
				switch ev.(type) {
				case EventFoo:
					evCast := ev.(EventFoo)
					updaterFoo.Publish(evCast)
				case EventBar:
					evCast := ev.(EventBar)
					updaterBar.Publish(evCast)
				case EventBaz:
					evCast := ev.(EventBaz)
					updaterBaz.Publish(evCast)
				}
			}

			if err := ExpectOnlyEvents(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectOnlyEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectEventsFunc(t *testing.T) {
	tests := []struct {
		name         string
		events       []any
		expectEvents []EventFunc
		wantErr      bool
	}{
		{
			name:         "No expectations",
			events:       []any{EventFoo{}},
			expectEvents: []EventFunc{},
			wantErr:      false,
		},
		{
			name:   "One event",
			events: []any{EventFoo{42}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "One event with specific value",
			events: []any{EventFoo{43}, EventFoo{42}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "One event with wrong value",
			events: []any{EventFoo{43}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: true,
		},
		{
			name:   "Two events with specific values",
			events: []any{EventFoo{42}, EventFoo{42}, EventBar{"42"}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
				{
					EventBar{},
					func(event any) (bool, error) {
						ev := event.(EventBar)
						if ev.Value == "42" {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: false,
		},
	}

	bus := NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 1 * time.Millisecond

			client := bus.Client("testClient")
			updaterFoo := eventbus.Publish[EventFoo](client)
			updaterBar := eventbus.Publish[EventBar](client)
			updaterBaz := eventbus.Publish[EventBaz](client)

			for _, ev := range tt.events {
				switch ev.(type) {
				case EventFoo:
					evCast := ev.(EventFoo)
					updaterFoo.Publish(evCast)
				case EventBar:
					evCast := ev.(EventBar)
					updaterBar.Publish(evCast)
				case EventBaz:
					evCast := ev.(EventBaz)
					updaterBaz.Publish(evCast)
				}
			}

			if err := ExpectEventsFunc(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectOnlyEventsFunc(t *testing.T) {
	tests := []struct {
		name         string
		events       []any
		expectEvents []EventFunc
		wantErr      bool
	}{
		{
			name:         "No expectations",
			events:       []any{EventFoo{}},
			expectEvents: []EventFunc{},
			wantErr:      false,
		},
		{
			name:   "One event",
			events: []any{EventFoo{42}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "One event with specific value",
			events: []any{EventFoo{43}, EventFoo{42}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: true,
		},
		{
			name:   "One event with wrong value",
			events: []any{EventFoo{43}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, fmt.Errorf("expected value 42, got %v", ev.Value)
					},
				},
			},
			wantErr: true,
		},
		{
			name:   "Two events with specific values",
			events: []any{EventFoo{42}, EventFoo{42}, EventBar{"42"}},
			expectEvents: []EventFunc{
				{
					EventFoo{},
					func(event any) (bool, error) {
						ev := event.(EventFoo)
						if ev.Value == 42 {
							return true, nil
						}
						return false, nil
					},
				},
				{
					EventBar{},
					func(event any) (bool, error) {
						ev := event.(EventBar)
						if ev.Value == "42" {
							return true, nil
						}
						return false, nil
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := NewBus(t)
			tw := NewWatcher(t, bus)

			client := bus.Client("testClient")
			updaterFoo := eventbus.Publish[EventFoo](client)
			updaterBar := eventbus.Publish[EventBar](client)
			updaterBaz := eventbus.Publish[EventBaz](client)

			for _, ev := range tt.events {
				switch ev.(type) {
				case EventFoo:
					evCast := ev.(EventFoo)
					updaterFoo.Publish(evCast)
				case EventBar:
					evCast := ev.(EventBar)
					updaterBar.Publish(evCast)
				case EventBaz:
					evCast := ev.(EventBaz)
					updaterBaz.Publish(evCast)
				}
			}

			if err := ExpectOnlyEventsFunc(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
