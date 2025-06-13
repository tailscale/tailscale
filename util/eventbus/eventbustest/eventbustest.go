package eventbustest

import (
	"errors"
	"fmt"
	"time"

	"tailscale.com/util/eventbus"
)

func NewTestWatcher(d *eventbus.Debugger) *TestWatcher {
	tw := &TestWatcher{
		mon:     d.WatchBus(),
		TimeOut: 5 * time.Second,
		done:    make(chan bool, 1),
		events:  make(chan any, 100),
	}
	go tw.watch()
	return tw
}

type TestWatcher struct {
	mon     *eventbus.Subscriber[eventbus.RoutedEvent]
	events  chan any
	done    chan bool
	TimeOut time.Duration
}

// Expect is a particular implementation of ExpectFunc that tests for the
// existence of an Event without caring about the contents of it.
//
// Example usage:
//
//	bus := eventbus.New()
//	defer bus.Close()
//
//	tw := bus.Debugger().NewTestWatcher()
//	defer tw.Done()
//
//	somethingThatEmitsSomeEvent()
//	if err := eventbus.Expect[SomeEvent](tw); err != nil {
//	  t.Error(err.Error())
//	}
func Expect[T any](tw *TestWatcher) error {
	return ExpectFunc(tw, func(event T) bool { return true })
}

// ExpectFunc tests for a particular event but also a particular shape of said event.
// This allows for looking for a single event with a specific value, or a
// particular event in a pile of SomeEvent.
//
// Example usage of looking for one event with a specific value:
//
//	bus := eventbus.New()
//	defer bus.Close()
//
//	tw := bus.Debugger().NewTestWatcher()
//	defer tw.Done()
//
//	somethingThatEmitsSomeEvent()
//	expectedValue := 42
//	if err := eventbus.ExpectFunc(tw, func(event SomeEvent) bool {
//		if event.Value != expectedValue {
//			t.Errorf("expected %v, got %v", expected, event.External)
//		}
//		return true
//	}); err != nil {
//	  t.Error(err.Error())
//	}
func ExpectFunc[T any](tw *TestWatcher, test func(event T) bool) error {
	eventCount := 0
	for {
		select {
		case event := <-tw.events:
			eventCount = eventCount + 1
			if ev, ok := event.(T); ok {
				if test(ev) {
					return nil
				}
			}
		case <-time.After(tw.TimeOut):
			return fmt.Errorf("timed out waiting for event, saw %d events", eventCount)
		}
	}
}

// ExpectAfter is a particular implementation of ExpectAfterFunc that tests for the
// existence of an Event happening after another Event (same of different types)
// without caring about the contents of said Events.
//
// Example usage:
//
//	bus := eventbus.New()
//	defer bus.Close()
//
//	tw := bus.Debugger().NewTestWatcher()
//	defer tw.Done()
//
//	somethingThatEmitsSomeEventAndAnotherEvent()
//	if err := eventbus.ExpectAfter[SomeEvent, AnotherEvent](tw); err != nil {
//	  t.Error(err.Error())
//	}
func ExpectAfter[A any, B any](tw *TestWatcher) error {
	return ExpectAfterFunc(tw, func(event A) bool { return true }, func(after B) bool { return true })
}

// ExpectAfterFunc test for the existence of SomeEvent happening after AnotherEvent,
// while also allowing for testing the content of those events or filtering them.
//
// Example usage:
//
//	bus := eventbus.New()
//	defer bus.Close()
//
//	tw := bus.Debugger().NewTestWatcher()
//	defer tw.Done()
//
//	expectedValue := 42
//	testSomeEvent := func(event SomeEvent) bool {
//		if event.Value != expectedValue {
//			t.Errorf("expected %v, got %v", expected, event.External)
//		}
//		return true
//	}
//
//	filterAnotherEvent := func(event AnotherEvent) bool {
//		if event.Value != expectedValue {
//			return false
//		}
//		return true
//	}
//
//	somethingThatEmitsSomeEventAndAnotherEvent()
//	if err := eventbus.ExpectAfterFunc[SomeEvent, AnotherEvent](tw,
//		testSomeEvent, filterAnotherEvent); err != nil {
//		t.Error(err.Error())
//	}
func ExpectAfterFunc[A any, B any](tw *TestWatcher, test func(event A) bool, after func(event B) bool) error {
	var testSeen *A
	var afterSeen *B
	eventCount := 0
	for {
		select {
		case event := <-tw.events:
			eventCount = eventCount + 1
			if ev, ok := event.(B); ok {
				if after(ev) {
					afterSeen = &ev
					if testSeen != nil {
						return errors.New("the 'after' event appeared before the 'test' event")
					}
				}
			} else if ev, ok := event.(A); ok {
				if test(ev) {
					testSeen = &ev
					if afterSeen != nil {
						return nil
					}
				}
			}
		case <-time.After(tw.TimeOut):
			return fmt.Errorf("timed out waiting for event, saw %d events", eventCount)
		}
	}
}

func (tw *TestWatcher) watch() {
	for {
		select {
		case event := <-tw.mon.Events():
			tw.events <- event.Event
		case <-tw.done:
			tw.mon.Close()
			return
		}
	}
}

func (tw *TestWatcher) Done() {
	tw.done <- true
}
