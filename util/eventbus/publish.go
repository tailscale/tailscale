// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
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
	client  *Client
	stopCtx context.Context
	stop    context.CancelFunc
}

func newPublisher[T any](c *Client) *Publisher[T] {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &Publisher[T]{
		client:  c,
		stopCtx: ctx,
		stop:    cancel,
	}
	c.addPublisher(ret)
	return ret
}

// Close closes the publisher.
//
// Calls to Publish after Close silently do nothing.
func (p *Publisher[T]) Close() {
	// Just unblocks any active calls to Publish, no other
	// synchronization needed.
	p.stop()
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
	case <-p.stopCtx.Done():
		return
	default:
	}

	select {
	case p.client.publish() <- v:
	case <-p.stopCtx.Done():
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
