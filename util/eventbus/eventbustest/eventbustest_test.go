// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbustest_test

import (
	"fmt"
	"testing"
	"time"

	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
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

func TestExpectFilter(t *testing.T) {
	tests := []struct {
		name       string
		events     []int
		expectFunc any
		wantErr    bool
	}{
		{
			name:       "single event",
			events:     []int{42},
			expectFunc: eventbustest.Type[EventFoo](),
			wantErr:    false,
		},
		{
			name:       "multiple events, single expectation",
			events:     []int{42, 1, 2, 3, 4, 5},
			expectFunc: eventbustest.Type[EventFoo](),
			wantErr:    false,
		},
		{
			name:   "filter on event with function",
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

	bus := eventbustest.NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := eventbustest.NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 10 * time.Millisecond

			client := bus.Client("testClient")
			defer client.Close()
			updater := eventbus.Publish[EventFoo](client)

			for _, i := range tt.events {
				updater.Publish(EventFoo{i})
			}

			if err := eventbustest.Expect(tw, tt.expectFunc); (err != nil) != tt.wantErr {
				t.Errorf("ExpectFilter[EventFoo]: error = %v, wantErr %v", err, tt.wantErr)
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
			wantErr:      true,
		},
		{
			name:         "One event",
			events:       []any{EventFoo{}},
			expectEvents: []any{eventbustest.Type[EventFoo]()},
			wantErr:      false,
		},
		{
			name:         "Two events",
			events:       []any{EventFoo{}, EventBar{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      false,
		},
		{
			name:         "Two expected events with another in the middle",
			events:       []any{EventFoo{}, EventBaz{}, EventBar{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      false,
		},
		{
			name:         "Missing event",
			events:       []any{EventFoo{}, EventBaz{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      true,
		},
		{
			name:   "One event with specific value",
			events: []any{EventFoo{42}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: false,
		},
		{
			name:   "Two event with one specific value",
			events: []any{EventFoo{43}, EventFoo{42}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: false,
		},
		{
			name:   "One event with wrong value",
			events: []any{EventFoo{43}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: true,
		},
		{
			name:   "Two events with specific values",
			events: []any{EventFoo{42}, EventFoo{42}, EventBar{"42"}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
				func(ev EventBar) (bool, error) {
					if ev.Value == "42" {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: false,
		},
	}

	bus := eventbustest.NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := eventbustest.NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 10 * time.Millisecond

			client := bus.Client("testClient")
			defer client.Close()
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

			if err := eventbustest.Expect(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpectExactlyEventsFilter(t *testing.T) {
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
			wantErr:      true,
		},
		{
			name:         "One event",
			events:       []any{EventFoo{}},
			expectEvents: []any{eventbustest.Type[EventFoo]()},
			wantErr:      false,
		},
		{
			name:         "Two events",
			events:       []any{EventFoo{}, EventBar{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      false,
		},
		{
			name:         "Two expected events with another in the middle",
			events:       []any{EventFoo{}, EventBaz{}, EventBar{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      true,
		},
		{
			name:         "Missing event",
			events:       []any{EventFoo{}, EventBaz{}},
			expectEvents: []any{eventbustest.Type[EventFoo](), eventbustest.Type[EventBar]()},
			wantErr:      true,
		},
		{
			name:   "One event with value",
			events: []any{EventFoo{42}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: false,
		},
		{
			name:   "Two event with one specific value",
			events: []any{EventFoo{43}, EventFoo{42}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: true,
		},
		{
			name:   "One event with wrong value",
			events: []any{EventFoo{43}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: true,
		},
		{
			name:   "Two events with specific values",
			events: []any{EventFoo{42}, EventFoo{42}, EventBar{"42"}},
			expectEvents: []any{
				func(ev EventFoo) (bool, error) {
					if ev.Value == 42 {
						return true, nil
					}
					return false, nil
				},
				func(ev EventBar) (bool, error) {
					if ev.Value == "42" {
						return true, nil
					}
					return false, nil
				},
			},
			wantErr: true,
		},
	}

	bus := eventbustest.NewBus(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tw := eventbustest.NewWatcher(t, bus)
			// TODO(cmol): When synctest is out of experimental, use that instead:
			// https://go.dev/blog/synctest
			tw.TimeOut = 10 * time.Millisecond

			client := bus.Client("testClient")
			defer client.Close()
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

			if err := eventbustest.ExpectExactly(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
				t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
