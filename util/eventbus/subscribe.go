// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

type DeliveredEvent struct {
	Event any
	From  *Client
	To    *Client
}

// subscriber is a uniformly typed wrapper around Subscriber[T], so
// that debugging facilities can look at active subscribers.
type subscriber interface {
	subscribeType() reflect.Type
	// dispatch is a function that dispatches the head value in vals to
	// a subscriber, while also handling stop and incoming queue write
	// events.
	//
	// dispatch exists because of the strongly typed Subscriber[T]
	// wrapper around subscriptions: within the bus events are boxed in an
	// 'any', and need to be unpacked to their full type before delivery
	// to the subscriber. This involves writing to a strongly-typed
	// channel, so subscribeState cannot handle that dispatch by itself -
	// but if that strongly typed send blocks, we also need to keep
	// processing other potential sources of wakeups, which is how we end
	// up at this awkward type signature and sharing of internal state
	// through dispatch.
	dispatch(ctx context.Context, vals *queue[DeliveredEvent], acceptCh func() chan DeliveredEvent, snapshot chan chan []DeliveredEvent) bool
	Close()
}

// subscribeState handles dispatching of events received from a Bus.
type subscribeState struct {
	client *Client

	dispatcher *worker
	write      chan DeliveredEvent
	snapshot   chan chan []DeliveredEvent
	debug      hook[DeliveredEvent]

	outputsMu sync.Mutex
	outputs   map[reflect.Type]subscriber
}

func newSubscribeState(c *Client) *subscribeState {
	ret := &subscribeState{
		client:   c,
		write:    make(chan DeliveredEvent),
		snapshot: make(chan chan []DeliveredEvent),
		outputs:  map[reflect.Type]subscriber{},
	}
	ret.dispatcher = runWorker(ret.pump)
	return ret
}

func (q *subscribeState) pump(ctx context.Context) {
	var vals queue[DeliveredEvent]
	acceptCh := func() chan DeliveredEvent {
		if vals.Full() {
			return nil
		}
		return q.write
	}
	for {
		if !vals.Empty() {
			val := vals.Peek()
			sub := q.subscriberFor(val.Event)
			if sub == nil {
				// Raced with unsubscribe.
				vals.Drop()
				continue
			}
			if !sub.dispatch(ctx, &vals, acceptCh, q.snapshot) {
				return
			}

			if q.debug.active() {
				q.debug.run(DeliveredEvent{
					Event: val.Event,
					From:  val.From,
					To:    q.client,
				})
			}
		} else {
			// Keep the cases in this select in sync with
			// Subscriber.dispatch below. The only difference should be
			// that this select doesn't deliver queued values to
			// anyone, and unconditionally accepts new values.
			select {
			case val := <-q.write:
				vals.Add(val)
			case <-ctx.Done():
				return
			case ch := <-q.snapshot:
				ch <- vals.Snapshot()
			}
		}
	}
}

func (s *subscribeState) snapshotQueue() []DeliveredEvent {
	if s == nil {
		return nil
	}

	resp := make(chan []DeliveredEvent)
	select {
	case s.snapshot <- resp:
		return <-resp
	case <-s.dispatcher.Done():
		return nil
	}
}

func (s *subscribeState) subscribeTypes() []reflect.Type {
	if s == nil {
		return nil
	}

	s.outputsMu.Lock()
	defer s.outputsMu.Unlock()
	ret := make([]reflect.Type, 0, len(s.outputs))
	for t := range s.outputs {
		ret = append(ret, t)
	}
	return ret
}

func (s *subscribeState) addSubscriber(sub subscriber) {
	s.outputsMu.Lock()
	defer s.outputsMu.Unlock()
	t := sub.subscribeType()
	if s.outputs[t] != nil {
		panic(fmt.Errorf("double subscription for event %s", t))
	}
	s.outputs[t] = sub
	s.client.addSubscriber(t, s)
}

func (s *subscribeState) deleteSubscriber(t reflect.Type) {
	s.outputsMu.Lock()
	defer s.outputsMu.Unlock()
	delete(s.outputs, t)
	s.client.deleteSubscriber(t, s)
}

func (q *subscribeState) subscriberFor(val any) subscriber {
	q.outputsMu.Lock()
	defer q.outputsMu.Unlock()
	return q.outputs[reflect.TypeOf(val)]
}

// Close closes the subscribeState. It implicitly closes all Subscribers
// linked to this state, and any pending events are discarded.
func (s *subscribeState) close() {
	s.dispatcher.StopAndWait()

	var subs map[reflect.Type]subscriber
	s.outputsMu.Lock()
	subs, s.outputs = s.outputs, nil
	s.outputsMu.Unlock()
	for _, sub := range subs {
		sub.Close()
	}
}

func (s *subscribeState) closed() <-chan struct{} {
	return s.dispatcher.Done()
}

// A Subscriber delivers one type of event from a [Client].
type Subscriber[T any] struct {
	stop       stopFlag
	read       chan T
	unregister func()
}

func newSubscriber[T any](r *subscribeState) *Subscriber[T] {
	return &Subscriber[T]{
		read:       make(chan T),
		unregister: func() { r.deleteSubscriber(reflect.TypeFor[T]()) },
	}
}

func newMonitor[T any](attach func(fn func(T)) (cancel func())) *Subscriber[T] {
	ret := &Subscriber[T]{
		read: make(chan T, 100), // arbitrary, large
	}
	ret.unregister = attach(ret.monitor)
	return ret
}

func (s *Subscriber[T]) subscribeType() reflect.Type {
	return reflect.TypeFor[T]()
}

func (s *Subscriber[T]) monitor(debugEvent T) {
	select {
	case s.read <- debugEvent:
	case <-s.stop.Done():
	}
}

func (s *Subscriber[T]) dispatch(ctx context.Context, vals *queue[DeliveredEvent], acceptCh func() chan DeliveredEvent, snapshot chan chan []DeliveredEvent) bool {
	t := vals.Peek().Event.(T)
	for {
		// Keep the cases in this select in sync with subscribeState.pump
		// above. The only different should be that this select
		// delivers a value on s.read.
		select {
		case s.read <- t:
			vals.Drop()
			return true
		case val := <-acceptCh():
			vals.Add(val)
		case <-ctx.Done():
			return false
		case ch := <-snapshot:
			ch <- vals.Snapshot()
		}
	}
}

// Events returns a channel on which the subscriber's events are
// delivered.
func (s *Subscriber[T]) Events() <-chan T {
	return s.read
}

// Done returns a channel that is closed when the subscriber is
// closed.
func (s *Subscriber[T]) Done() <-chan struct{} {
	return s.stop.Done()
}

// Close closes the Subscriber, indicating the caller no longer wishes
// to receive this event type. After Close, receives on
// [Subscriber.Events] block for ever.
//
// If the Bus from which the Subscriber was created is closed,
// the Subscriber is implicitly closed and does not need to be closed
// separately.
func (s *Subscriber[T]) Close() {
	s.stop.Stop() // unblock receivers
	s.unregister()
}
