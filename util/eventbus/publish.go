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
	publisherName() string
}

// A Publisher publishes events on the bus.
type Publisher[T any] struct {
	bus     *Bus
	name    string
	stopCtx context.Context
	stop    context.CancelFunc
}

// PublisherOf returns a publisher for event type T on the given bus.
//
// The publisher's name should be a short, human-readable string that
// identifies this event publisher. The name is only visible through
// debugging APIs.
func PublisherOf[T any](b *Bus, name string) *Publisher[T] {
	ctx, cancel := context.WithCancel(context.Background())
	ret := &Publisher[T]{
		bus:     b,
		name:    name,
		stopCtx: ctx,
		stop:    cancel,
	}
	b.addPublisher(ret)
	return ret
}

func (p *Publisher[T]) publisherName() string { return p.name }

// Publish publishes event v on the bus.
func (p *Publisher[T]) Publish(v T) {
	// Check for just a stopped publisher or bus before trying to
	// write, so that once closed Publish consistently does nothing.
	select {
	case <-p.stopCtx.Done():
		return
	case <-p.bus.stop.WaitChan():
		return
	default:
	}

	select {
	case p.bus.write <- v:
	case <-p.stopCtx.Done():
	case <-p.bus.stop.WaitChan():
	}
}

// ShouldPublish reports whether anyone is subscribed to events of
// type T.
//
// ShouldPublish can be used to skip expensive event construction if
// nobody seems to care. Publishers must not assume that someone will
// definitely receive an event if ShouldPublish returns true.
func (p *Publisher[T]) ShouldPublish() bool {
	dests := p.bus.dest(reflect.TypeFor[T]())
	return len(dests) > 0
}

// Close closes the publisher, indicating that no further events will
// be published with it.
func (p *Publisher[T]) Close() {
	p.stop()
	p.bus.deletePublisher(p)
}
