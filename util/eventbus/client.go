// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"reflect"
	"sync"

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

	mu  sync.Mutex
	pub set.Set[publisher]
	sub *subscribeState // Lazily created on first subscribe
}

func (c *Client) Name() string { return c.name }

// Close closes the client. Implicitly closes all publishers and
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
}

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
	if c.sub == nil {
		c.sub = newSubscribeState(c)
	}
	return c.sub
}

func (c *Client) addPublisher(pub publisher) {
	c.mu.Lock()
	defer c.mu.Unlock()
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

// Subscribe requests delivery of events of type T through the given
// Queue. Panics if the queue already has a subscriber for T.
func Subscribe[T any](c *Client) *Subscriber[T] {
	r := c.subscribeState()
	s := newSubscriber[T](r)
	r.addSubscriber(s)
	return s
}

// Publisher returns a publisher for event type T using the given
// client.
func Publish[T any](c *Client) *Publisher[T] {
	p := newPublisher[T](c)
	c.addPublisher(p)
	return p
}
