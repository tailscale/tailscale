// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"reflect"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

// A Client can publish and subscribe to events on its attached
// bus. See [Publish] to publish events, and [Subscribe] to receive
// events.
//
// Subscribers that share the same client receive events one at a
// time, in the order they were published.
type Client struct {
	name         string
	bus          *Bus
	publishDebug hook[PublishedEvent]

	mu   syncs.Mutex
	pub  set.Set[publisher]
	sub  *subscribeState // Lazily created on first subscribe
	stop stopFlag        // signaled on Close
}

func (c *Client) Name() string { return c.name }

func (c *Client) logger() logger.Logf { return c.bus.logger() }

// Close closes the client. It implicitly closes all publishers and
// subscribers obtained from this client.
func (c *Client) Close() {
	var (
		pub set.Set[publisher]
		sub *subscribeState
	)

	c.mu.Lock()
	pub, c.pub = c.pub, nil
	sub, c.sub = c.sub, nil
	c.mu.Unlock()

	if sub != nil {
		sub.close()
	}
	for p := range pub {
		p.Close()
	}
	c.stop.Stop()
}

func (c *Client) isClosed() bool { return c.pub == nil && c.sub == nil }

// Done returns a channel that is closed when [Client.Close] is called.
// The channel is closed after all the publishers and subscribers governed by
// the client have been closed.
func (c *Client) Done() <-chan struct{} { return c.stop.Done() }

func (c *Client) snapshotSubscribeQueue() []DeliveredEvent {
	return c.peekSubscribeState().snapshotQueue()
}

func (c *Client) peekSubscribeState() *subscribeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sub
}

func (c *Client) publishTypes() []reflect.Type {
	c.mu.Lock()
	defer c.mu.Unlock()
	ret := make([]reflect.Type, 0, len(c.pub))
	for pub := range c.pub {
		ret = append(ret, pub.publishType())
	}
	return ret
}

func (c *Client) subscribeTypes() []reflect.Type {
	return c.peekSubscribeState().subscribeTypes()
}

func (c *Client) subscribeState() *subscribeState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.subscribeStateLocked()
}

func (c *Client) subscribeStateLocked() *subscribeState {
	if c.sub == nil {
		c.sub = newSubscribeState(c)
	}
	return c.sub
}

func (c *Client) addPublisher(pub publisher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed() {
		panic("cannot Publish on a closed client")
	}
	c.pub.Add(pub)
}

func (c *Client) deletePublisher(pub publisher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pub.Delete(pub)
}

func (c *Client) addSubscriber(t reflect.Type, s *subscribeState) {
	c.bus.subscribe(t, s)
}

func (c *Client) deleteSubscriber(t reflect.Type, s *subscribeState) {
	c.bus.unsubscribe(t, s)
}

func (c *Client) publish() chan<- PublishedEvent {
	return c.bus.write
}

func (c *Client) shouldPublish(t reflect.Type) bool {
	return c.publishDebug.active() || c.bus.shouldPublish(t)
}

// Subscribe requests delivery of events of type T through the given client.
// It panics if c already has a subscriber for type T, or if c is closed.
func Subscribe[T any](c *Client) *Subscriber[T] {
	// Hold the client lock throughout the subscription process so that a caller
	// attempting to subscribe on a closed client will get a useful diagnostic
	// instead of a random panic from inside the subscriber plumbing.
	c.mu.Lock()
	defer c.mu.Unlock()

	// The caller should not race subscriptions with close, give them a useful
	// diagnostic at the call site.
	if c.isClosed() {
		panic("cannot Subscribe on a closed client")
	}

	r := c.subscribeStateLocked()
	s := newSubscriber[T](r, logfForCaller(c.logger()))
	r.addSubscriber(s)
	return s
}

// SubscribeFunc is like [Subscribe], but calls the provided func for each
// event of type T.
//
// A SubscriberFunc calls f synchronously from the client's goroutine.
// This means the callback must not block for an extended period of time,
// as this will block the subscriber and slow event processing for all
// subscriptions on c.
func SubscribeFunc[T any](c *Client, f func(T)) *SubscriberFunc[T] {
	c.mu.Lock()
	defer c.mu.Unlock()

	// The caller should not race subscriptions with close, give them a useful
	// diagnostic at the call site.
	if c.isClosed() {
		panic("cannot SubscribeFunc on a closed client")
	}

	r := c.subscribeStateLocked()
	s := newSubscriberFunc[T](r, f, logfForCaller(c.logger()))
	r.addSubscriber(s)
	return s
}

// Publish returns a publisher for event type T using the given client.
// It panics if c is closed.
func Publish[T any](c *Client) *Publisher[T] {
	p := newPublisher[T](c)
	c.addPublisher(p)
	return p
}
