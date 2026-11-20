// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package mixed uses event types in ways that eventbuscheck should and should
// not report.
package mixed

import (
	"testing"

	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
)

// PubValueSubPtr is published by value but subscribed by pointer.
type PubValueSubPtr struct{}

// PubBoth is published both by value and by pointer.
type PubBoth struct{}

// InjectPtr is published by value but injected by pointer in a test.
type InjectPtr struct{}

// ExpectPtr is published by value but expected by pointer in a test.
type ExpectPtr struct{}

// PtrOnly is consistently used by pointer, which is fine.
type PtrOnly struct{}

// ValueOnly is consistently used by value, which is fine.
type ValueOnly struct{}

func onPubValueSubPtr(*PubValueSubPtr) {}

func use(c *eventbus.Client, t *testing.T, inj *eventbustest.Injector, tw *eventbustest.Watcher) {
	eventbus.Publish[PubValueSubPtr](c)
	eventbus.SubscribeFunc(c, onPubValueSubPtr)

	eventbus.Publish[PubBoth](c)
	eventbus.Publish[*PubBoth](c)

	eventbus.Publish[InjectPtr](c)
	eventbustest.Inject(inj, &InjectPtr{})

	eventbus.Publish[ExpectPtr](c)
	eventbustest.Expect(tw, func(*ExpectPtr) {})

	eventbus.Publish[*PtrOnly](c)
	eventbus.Subscribe[*PtrOnly](c)
	eventbustest.Expect(tw, eventbustest.Type[*PtrOnly]())

	eventbus.Publish[ValueOnly](c)
	eventbus.SubscribeFunc(c, func(ValueOnly) {})
	eventbustest.Expect(tw, eventbustest.EqualTo(ValueOnly{}))
}
