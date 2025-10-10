// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbustest_test

import (
	"flag"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"

	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
)

var doDebug = flag.Bool("debug", false, "Enable debug logging")

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
		wantErr    string // if non-empty, an error is expected containing this text
	}{
		{
			name:       "single event",
			events:     []int{42},
			expectFunc: eventbustest.Type[EventFoo](),
		},
		{
			name:       "multiple events, single expectation",
			events:     []int{42, 1, 2, 3, 4, 5},
			expectFunc: eventbustest.Type[EventFoo](),
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
		},
		{
			name:   "filter-with-nil-error",
			events: []int{1, 2, 3},
			expectFunc: func(event EventFoo) error {
				if event.Value > 10 {
					return fmt.Errorf("value > 10: %d", event.Value)
				}
				return nil
			},
		},
		{
			name:   "filter-with-non-nil-error",
			events: []int{100, 200, 300},
			expectFunc: func(event EventFoo) error {
				if event.Value > 10 {
					return fmt.Errorf("value > 10: %d", event.Value)
				}
				return nil
			},
			wantErr: "value > 10",
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
			wantErr: "expected 42, got 24",
		},
		{
			name:       "equal-values",
			events:     []int{23},
			expectFunc: eventbustest.EqualTo(EventFoo{Value: 23}),
		},
		{
			name:       "unequal-values",
			events:     []int{37},
			expectFunc: eventbustest.EqualTo(EventFoo{Value: 23}),
			wantErr:    "wrong result (-got, +want)",
		},
		{
			name:   "no events",
			events: []int{},
			expectFunc: func(event EventFoo) (bool, error) {
				return true, nil
			},
			wantErr: "timed out waiting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := eventbustest.NewBus(t)

				if *doDebug {
					eventbustest.LogAllEvents(t, bus)
				}
				tw := eventbustest.NewWatcher(t, bus)

				client := bus.Client("testClient")
				updater := eventbus.Publish[EventFoo](client)

				for _, i := range tt.events {
					updater.Publish(EventFoo{i})
				}

				synctest.Wait()

				if err := eventbustest.Expect(tw, tt.expectFunc); err != nil {
					if tt.wantErr == "" {
						t.Errorf("Expect[EventFoo]: unexpected error: %v", err)
					} else if !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("Expect[EventFoo]: err = %v, want %q", err, tt.wantErr)
					} else {
						t.Logf("Got expected error: %v (OK)", err)
					}
				} else if tt.wantErr != "" {
					t.Errorf("Expect[EventFoo]: unexpectedly succeeded, want error %q", tt.wantErr)
				}
			})
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := eventbustest.NewBus(t)

				tw := eventbustest.NewWatcher(t, bus)

				client := bus.Client("testClient")
				updaterFoo := eventbus.Publish[EventFoo](client)
				updaterBar := eventbus.Publish[EventBar](client)
				updaterBaz := eventbus.Publish[EventBaz](client)

				for _, ev := range tt.events {
					switch ev := ev.(type) {
					case EventFoo:
						evCast := ev
						updaterFoo.Publish(evCast)
					case EventBar:
						evCast := ev
						updaterBar.Publish(evCast)
					case EventBaz:
						evCast := ev
						updaterBaz.Publish(evCast)
					}
				}

				synctest.Wait()
				if err := eventbustest.Expect(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
					t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
				}
			})
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				bus := eventbustest.NewBus(t)

				tw := eventbustest.NewWatcher(t, bus)

				client := bus.Client("testClient")
				updaterFoo := eventbus.Publish[EventFoo](client)
				updaterBar := eventbus.Publish[EventBar](client)
				updaterBaz := eventbus.Publish[EventBaz](client)

				for _, ev := range tt.events {
					switch ev := ev.(type) {
					case EventFoo:
						evCast := ev
						updaterFoo.Publish(evCast)
					case EventBar:
						evCast := ev
						updaterBar.Publish(evCast)
					case EventBaz:
						evCast := ev
						updaterBaz.Publish(evCast)
					}
				}

				synctest.Wait()
				if err := eventbustest.ExpectExactly(tw, tt.expectEvents...); (err != nil) != tt.wantErr {
					t.Errorf("ExpectEvents: error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		})
	}
}
