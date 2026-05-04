// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"reflect"
)

// publisher is a uniformly typed wrapper around publisherCore so that
// debugging facilities can enumerate active publishers on a [Client]
// and report the types each one publishes. The interface is
// implemented by the non-generic *publisherCore (not by the typed
// user-facing *Publisher[T]); this keeps the bus's per-Client
// publisher set, and the publisher itab/dictionary, free of
// per-T duplication.
type publisher interface {
	publishType() reflect.Type
	Close()
}

// A Publisher publishes typed events on a bus.
type Publisher[T any] struct {
	// Implementation note: Publisher[T] is a thin user-facing facade over a
	// non-generic *publisherCore. Carrying T on the public type preserves the
	// typed API of Publish(v T), but all of the actual state (the *Client
	// back-pointer, the stop flag, and the cached reflect.Type used by
	// diagnostic introspection) lives on the core and is not duplicated per T.
	//
	// The diagnostic surface that motivates the publisher interface
	// (Debugger.PublishTypes) is served by *publisherCore directly, so adding
	// new typed publishers does not pay an itab+dictionary cost just to satisfy
	// diagnostic enumeration.
	core *publisherCore
}

// publisherCore is the non-generic implementation of a Publisher.
// It implements the package-private publisher interface; the bus's
// outputs map and itab key on this single type, not on Publisher[T].
type publisherCore struct {
	client *Client
	stop   stopFlag
	typ    reflect.Type // cached reflect.TypeFor[T]()
}

func newPublisher[T any](c *Client) *Publisher[T] {
	return &Publisher[T]{
		core: &publisherCore{
			client: c,
			typ:    reflect.TypeFor[T](),
		},
	}
}

// Close closes the publisher.
//
// Calls to Publish after Close silently do nothing.
//
// If the Bus or Client from which the Publisher was created is closed,
// the Publisher is implicitly closed and does not need to be closed
// separately.
func (p *Publisher[T]) Close() { p.core.Close() }

// Close implements the publisher interface and the user-facing
// (*Publisher[T]).Close.
func (c *publisherCore) Close() {
	// Just unblocks any active calls to Publish, no other
	// synchronization needed.
	c.stop.Stop()
	c.client.deletePublisher(c)
}

// publishType implements the publisher interface.
func (c *publisherCore) publishType() reflect.Type { return c.typ }

// Publish publishes event v on the bus.
func (p *Publisher[T]) Publish(v T) {
	publish(p.core, v)
}

// publish is the non-generic body of Publisher[T].Publish. The only
// per-T work is the boxing of v into evt.Event (an `any` field) and
// the construction of the PublishedEvent struct itself; all of the
// channel/select dance is shared across every T.
func publish(c *publisherCore, v any) {
	// Check for just a stopped publisher or bus before trying to
	// write, so that once closed Publish consistently does nothing.
	select {
	case <-c.stop.Done():
		return
	default:
	}

	evt := PublishedEvent{
		Event: v,
		From:  c.client,
	}

	select {
	case c.client.publish() <- evt:
	case <-c.stop.Done():
	}
}

// ShouldPublish reports whether anyone is subscribed to the events
// that this publisher emits.
//
// ShouldPublish can be used to skip expensive event construction if
// nobody seems to care. Publishers must not assume that someone will
// definitely receive an event if ShouldPublish returns true.
func (p *Publisher[T]) ShouldPublish() bool {
	return p.core.client.shouldPublish(p.core.typ)
}
