// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

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
	dispatch(vals *queue, stop goroutineShutdownWorker, acceptCh func() chan any) bool
	Close()
}

// subscribeState handles dispatching of events received from a Bus.
type subscribeState struct {
	client *Client

	write    chan any
	stop     goroutineShutdownControl
	snapshot chan chan []any

	outputsMu sync.Mutex
	outputs   map[reflect.Type]subscriber
}

func newSubscribeState(c *Client) *subscribeState {
	stopCtl, stopWorker := newGoroutineShutdown()
	ret := &subscribeState{
		client:   c,
		write:    make(chan any),
		stop:     stopCtl,
		snapshot: make(chan chan []any),
		outputs:  map[reflect.Type]subscriber{},
	}
	go ret.pump(stopWorker)
	return ret
}

func (q *subscribeState) pump(stop goroutineShutdownWorker) {
	defer stop.Done()
	var vals queue
	acceptCh := func() chan any {
		if vals.Full() {
			return nil
		}
		return q.write
	}
	for {
		if !vals.Empty() {
			val := vals.Peek()
			sub := q.subscriberFor(val)
			if sub == nil {
				// Raced with unsubscribe.
				vals.Drop()
				continue
			}
			if !sub.dispatch(&vals, stop, acceptCh) {
				return
			}
		} else {
			// Keep the cases in this select in sync with
			// Subscriber.dispatch below. The only different should be
			// that this select doesn't deliver queued values to
			// anyone, and unconditionally accepts new values.
			select {
			case val := <-q.write:
				vals.Add(val)
			case <-stop.Stop():
				return
			case ch := <-q.snapshot:
				ch <- vals.Snapshot()
			}
		}
	}
}

func (s *subscribeState) addSubscriber(t reflect.Type, sub subscriber) {
	s.outputsMu.Lock()
	defer s.outputsMu.Unlock()
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

// Close closes the subscribeState. Implicitly closes all Subscribers
// linked to this state, and any pending events are discarded.
func (s *subscribeState) close() {
	s.stop.StopAndWait()

	var subs map[reflect.Type]subscriber
	s.outputsMu.Lock()
	subs, s.outputs = s.outputs, nil
	s.outputsMu.Unlock()
	for _, sub := range subs {
		sub.Close()
	}
}

// A Subscriber delivers one type of event from a [Client].
type Subscriber[T any] struct {
	doneCtx context.Context
	done    context.CancelFunc
	recv    *subscribeState
	read    chan T
}

func newSubscriber[T any](r *subscribeState) *Subscriber[T] {
	t := reflect.TypeFor[T]()

	ctx, cancel := context.WithCancel(context.Background())
	ret := &Subscriber[T]{
		doneCtx: ctx,
		done:    cancel,
		recv:    r,
		read:    make(chan T),
	}
	r.addSubscriber(t, ret)

	return ret
}

func (s *Subscriber[T]) subscribeType() reflect.Type {
	return reflect.TypeFor[T]()
}

func (s *Subscriber[T]) dispatch(vals *queue, stop goroutineShutdownWorker, acceptCh func() chan any) bool {
	t := vals.Peek().(T)
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
		case <-stop.Stop():
			return false
		case ch := <-s.recv.snapshot:
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
	return s.doneCtx.Done()
}

// Close closes the Subscriber, indicating the caller no longer wishes
// to receive this event type. After Close, receives on
// [Subscriber.Events] block for ever.
func (s *Subscriber[T]) Close() {
	s.done() // unblock receivers
	s.recv.deleteSubscriber(reflect.TypeFor[T]())
}
