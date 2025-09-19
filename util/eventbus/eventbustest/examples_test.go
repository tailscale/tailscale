// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbustest_test

import (
	"testing"

	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestExample_Expect(t *testing.T) {
	type eventOfInterest struct{}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updater := eventbus.Publish[eventOfInterest](client)
	updater.Publish(eventOfInterest{})

	if err := eventbustest.Expect(tw, eventbustest.Type[eventOfInterest]()); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_Expect_WithFunction(t *testing.T) {
	type eventOfInterest struct {
		value int
	}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updater := eventbus.Publish[eventOfInterest](client)
	updater.Publish(eventOfInterest{43})
	updater.Publish(eventOfInterest{42})

	// Look for an event of eventOfInterest with a specific value
	if err := eventbustest.Expect(tw, func(event eventOfInterest) (bool, error) {
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

func TestExample_Expect_MultipleEvents(t *testing.T) {
	type eventOfInterest struct{}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct{}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{})

	// Even though three events was published, we just care about the two
	if err := eventbustest.Expect(tw,
		eventbustest.Type[eventOfInterest](),
		eventbustest.Type[eventOfCuriosity]()); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectExactly_MultipleEvents(t *testing.T) {
	type eventOfInterest struct{}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct{}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{})

	// Will fail as more events than the two expected comes in
	if err := eventbustest.ExpectExactly(tw,
		eventbustest.Type[eventOfInterest](),
		eventbustest.Type[eventOfCuriosity]()); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
}

func TestExample_Expect_WithMultipleFunctions(t *testing.T) {
	type eventOfInterest struct {
		value int
	}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct {
		value string
	}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{42})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{"42"})

	interest := func(event eventOfInterest) (bool, error) {
		if event.value == 42 {
			return true, nil
		}
		return false, nil
	}
	curiosity := func(event eventOfCuriosity) (bool, error) {
		if event.value == "42" {
			return true, nil
		}
		return false, nil
	}

	// Will fail as more events than the two expected comes in
	if err := eventbustest.Expect(tw, interest, curiosity); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// OK
}

func TestExample_ExpectExactly_WithMultipleFunctions(t *testing.T) {
	type eventOfInterest struct {
		value int
	}
	type eventOfNoConcern struct{}
	type eventOfCuriosity struct {
		value string
	}

	bus := eventbustest.NewBus(t)
	tw := eventbustest.NewWatcher(t, bus)

	client := bus.Client("testClient")
	updaterInterest := eventbus.Publish[eventOfInterest](client)
	updaterConcern := eventbus.Publish[eventOfNoConcern](client)
	updaterCuriosity := eventbus.Publish[eventOfCuriosity](client)
	updaterInterest.Publish(eventOfInterest{42})
	updaterConcern.Publish(eventOfNoConcern{})
	updaterCuriosity.Publish(eventOfCuriosity{"42"})

	interest := func(event eventOfInterest) (bool, error) {
		if event.value == 42 {
			return true, nil
		}
		return false, nil
	}
	curiosity := func(event eventOfCuriosity) (bool, error) {
		if event.value == "42" {
			return true, nil
		}
		return false, nil
	}

	// Will fail as more events than the two expected comes in
	if err := eventbustest.ExpectExactly(tw, interest, curiosity); err != nil {
		t.Log(err.Error())
	} else {
		t.Log("OK")
	}
	// Output:
	// expected event type eventbustest.eventOfCuriosity, saw eventbustest.eventOfNoConcern, at index 1
}
