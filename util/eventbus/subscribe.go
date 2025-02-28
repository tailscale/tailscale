// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"fmt"
	"reflect"
	"sync"
)

type dispatchFn func(vals *queue, stop goroutineShutdownWorker, acceptCh func() chan any) bool

// A Queue receives events from a Bus.
//
// To receive events through the queue, see [Subscribe]. Subscribers
// that share the same Queue receive events one at time, in the order
// they were published.
type Queue struct {
	bus  *Bus
	name string

	write    chan any
	stop     goroutineShutdownControl
	snapshot chan chan []any

	outputsMu sync.Mutex
	outputs   map[reflect.Type]dispatchFn
}

func newQueue(b *Bus, name string) *Queue {
	stopCtl, stopWorker := newGoroutineShutdown()
	ret := &Queue{
		bus:      b,
		name:     name,
		write:    make(chan any),
		stop:     stopCtl,
		snapshot: make(chan chan []any),
		outputs:  map[reflect.Type]dispatchFn{},
	}
	b.addQueue(ret)
	go ret.pump(stopWorker)
	return ret
}

func (q *Queue) pump(stop goroutineShutdownWorker) {
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
			fn := q.dispatchFn(val)
			if fn == nil {
				// Raced with unsubscribe.
				vals.Drop()
				continue
			}
			if !fn(&vals, stop, acceptCh) {
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

// A Subscriber delivers one type of event from a [Queue].
type Subscriber[T any] struct {
	recv *Queue
	read chan T
}

func (s *Subscriber[T]) dispatch(vals *queue, stop goroutineShutdownWorker, acceptCh func() chan any) bool {
	t := vals.Peek().(T)
	for {
		// Keep the cases in this select in sync with Queue.pump
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

// Close shuts down the Subscriber, indicating the caller no longer
// wishes to receive these events. After Close, receives on
// [Subscriber.Chan] block for ever.
func (s *Subscriber[T]) Close() {
	t := reflect.TypeFor[T]()
	s.recv.bus.unsubscribe(t, s.recv)
	s.recv.deleteDispatchFn(t)
}

func (q *Queue) dispatchFn(val any) dispatchFn {
	q.outputsMu.Lock()
	defer q.outputsMu.Unlock()
	return q.outputs[reflect.ValueOf(val).Type()]
}

func (q *Queue) addDispatchFn(t reflect.Type, fn dispatchFn) {
	q.outputsMu.Lock()
	defer q.outputsMu.Unlock()
	if q.outputs[t] != nil {
		panic(fmt.Errorf("double subscription for event %s", t))
	}
	q.outputs[t] = fn
}

func (q *Queue) deleteDispatchFn(t reflect.Type) {
	q.outputsMu.Lock()
	defer q.outputsMu.Unlock()
	delete(q.outputs, t)
}

// Done returns a channel that is closed when the Queue is closed.
func (q *Queue) Done() <-chan struct{} {
	return q.stop.WaitChan()
}

// Close closes the queue. All Subscribers attached to the queue are
// implicitly closed, and any pending events are discarded.
func (q *Queue) Close() {
	q.stop.StopAndWait()
	q.bus.deleteQueue(q)
}

// Subscribe requests delivery of events of type T through the given
// Queue. Panics if the queue already has a subscriber for T.
func Subscribe[T any](r *Queue) Subscriber[T] {
	t := reflect.TypeFor[T]()
	ret := Subscriber[T]{
		recv: r,
		read: make(chan T),
	}
	r.addDispatchFn(t, ret.dispatch)
	r.bus.subscribe(t, r)

	return ret
}
