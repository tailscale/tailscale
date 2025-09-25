// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"reflect"
)

// publisher is a uniformly typed wrapper around Publisher[T], so that
// debugging facilities can look at active publishers.
type publisher interface {
	publishType() reflect.Type
	Close()
}

// A Publisher publishes typed events on a bus.
type Publisher[T any] struct {
	client *Client
	stop   stopFlag
}

func newPublisher[T any](c *Client) *Publisher[T] {
	return &Publisher[T]{client: c}
}

// Close closes the publisher.
//
// Calls to Publish after Close silently do nothing.
//
// If the Bus or Client from which the Publisher was created is closed,
// the Publisher is implicitly closed and does not need to be closed
// separately.
func (p *Publisher[T]) Close() {
	// Just unblocks any active calls to Publish, no other
	// synchronization needed.
	p.stop.Stop()
	p.client.deletePublisher(p)
}

func (p *Publisher[T]) publishType() reflect.Type {
	return reflect.TypeFor[T]()
}

// Publish publishes event v on the bus.
func (p *Publisher[T]) Publish(v T) {
	// Check for just a stopped publisher or bus before trying to
	// write, so that once closed Publish consistently does nothing.
	select {
	case <-p.stop.Done():
		return
	default:
	}

	evt := PublishedEvent{
		Event: v,
		From:  p.client,
	}

	select {
	case p.client.publish() <- evt:
	case <-p.stop.Done():
	}
}

// ShouldPublish reports whether anyone is subscribed to the events
// that this publisher emits.
//
// ShouldPublish can be used to skip expensive event construction if
// nobody seems to care. Publishers must not assume that someone will
// definitely receive an event if ShouldPublish returns true.
func (p *Publisher[T]) ShouldPublish() bool {
	return p.client.shouldPublish(reflect.TypeFor[T]())
}
