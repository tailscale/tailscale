// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbustest

import (
	"testing"

	"tailscale.com/util/eventbus"
)

func TestExample_Expect(t *testing.T) {
	type eventOfInterest struct{}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updater := eventbus.Publish[eventOfInterest](client)
	updater.Publish(eventOfInterest{})

	if err := Expect[eventOfInterest](tw); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectFunc(t *testing.T) {
	type eventOfInterest struct {
		value int
	}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updater := eventbus.Publish[eventOfInterest](client)
	updater.Publish(eventOfInterest{43})
	updater.Publish(eventOfInterest{42})

	// Look for an event of eventOfInterest with a specific value
	if err := ExpectFunc(tw, func(event eventOfInterest) (bool, error) {
		if event.value != 42 {
			return false, nil // Look for another event with the expected value.
			// You could alternatively return an error here to ensure that the
			// first seen eventOfInterest matches the value:
			// return false, fmt.Errorf("expected 42, got %d", event.value)
		}
		return true, nil
	}); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectEvents(t *testing.T) {
	type eventOfInterest struct{}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct{}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{})

	// Even though three events was published, we just care about the two
	if err := ExpectEvents(tw, eventOfInterest{}, eventOfCuriosity{}); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectOnlyEvents(t *testing.T) {
	type eventOfInterest struct{}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct{}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{})

	// Will fail as more events than the two expected comes in
	if err := ExpectOnlyEvents(tw, eventOfInterest{}, eventOfCuriosity{}); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
}

func TestExample_ExpectEventsFunc(t *testing.T) {
	type eventOfInterest struct {
		value int
	}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct {
		value string
	}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{42})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{"42"})

	interest := EventFunc{eventOfInterest{}, func(event any) (bool, error) {
		ev := event.(eventOfInterest)
		if ev.value == 42 {
			return true, nil
		}
		return false, nil
	}}
	curiosity := EventFunc{eventOfCuriosity{}, func(event any) (bool, error) {
		ev := event.(eventOfCuriosity)
		if ev.value == "42" {
			return true, nil
		}
		return false, nil
	}}

	// Will fail as more events than the two expected comes in
	if err := ExpectEventsFunc(tw, interest, curiosity); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectOnlyEventsFunc(t *testing.T) {
	type eventOfInterest struct {
		value int
	}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct {
		value string
	}

	bus := NewBus(t)
	tw := NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{42})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{"42"})

	interest := EventFunc{eventOfInterest{}, func(event any) (bool, error) {
		ev := event.(eventOfInterest)
		if ev.value == 42 {
			return true, nil
		}
		return false, nil
	}}
	curiosity := EventFunc{eventOfCuriosity{}, func(event any) (bool, error) {
		ev := event.(eventOfCuriosity)
		if ev.value == "42" {
			return true, nil
		}
		return false, nil
	}}

	// Will fail as more events than the two expected comes in
	if err := ExpectOnlyEventsFunc(tw, interest, curiosity); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// expected event type eventbustest.eventOfCuriosity, saw eventbustest.eventOfNoConcern, at index 1
}
