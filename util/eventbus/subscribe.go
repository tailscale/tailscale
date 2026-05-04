// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/cibuild"
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

	outputsMu syncs.Mutex
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

func (s *subscribeState) pump(ctx context.Context) {
	var vals queue[DeliveredEvent]
	acceptCh := func() chan DeliveredEvent {
		if vals.Full() {
			return nil
		}
		return s.write
	}
	for {
		if !vals.Empty() {
			val := vals.Peek()
			sub := s.subscriberFor(val.Event)
			if sub == nil {
				// Raced with unsubscribe.
				vals.Drop()
				continue
			}
			if !sub.dispatch(ctx, &vals, acceptCh, s.snapshot) {
				return
			}

			if s.debug.active() {
				s.debug.run(DeliveredEvent{
					Event: val.Event,
					From:  val.From,
					To:    s.client,
				})
			}
		} else {
			// Keep the cases in this select in sync with
			// Subscriber.dispatch and SubscriberFunc.dispatch below.
			// The only difference should be that this select doesn't deliver
			// queued values to anyone, and unconditionally accepts new values.
			select {
			case val := <-s.write:
				vals.Add(val)
			case <-ctx.Done():
				return
			case ch := <-s.snapshot:
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

func (s *subscribeState) subscriberFor(val any) subscriber {
	s.outputsMu.Lock()
	defer s.outputsMu.Unlock()
	return s.outputs[reflect.TypeOf(val)]
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
// Events are sent to the [Subscriber.Events] channel.
type Subscriber[T any] struct {
	stop       stopFlag
	read       chan T
	unregister func()
	logf       logger.Logf
	slow       *time.Timer // used to detect slow subscriber service
}

func newSubscriber[T any](r *subscribeState, logf logger.Logf) *Subscriber[T] {
	slow := time.NewTimer(0)
	slow.Stop() // reset in dispatch
	return &Subscriber[T]{
		read:       make(chan T),
		unregister: func() { r.deleteSubscriber(reflect.TypeFor[T]()) },
		logf:       logf,
		slow:       slow,
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

	start := time.Now()
	s.slow.Reset(slowSubscriberTimeout)
	defer s.slow.Stop()

	for {
		// Keep the cases in this select in sync with subscribeState.pump
		// above. The only difference should be that this select
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
		case <-s.slow.C:
			s.logf("subscriber for %T is slow (%v elapsed)", t, time.Since(start))
			s.slow.Reset(slowSubscriberTimeout)
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

// A SubscriberFunc delivers one type of event from a [Client].
// Events are forwarded synchronously to a function provided at construction.
type SubscriberFunc[T any] struct {
	// Implementation note: SubscriberFunc[T] is a thin facade over a
	// non-generic *subscriberFuncCore. All of the behavior — the
	// subscriber-interface implementation (Close, subscribeType, dispatch), the
	// slow-subscriber timer, the type assertion, and the user callback
	// invocation — lives on the core and is not instantiated per T. The only
	// per-T cost is the small forwarding Close method below.
	core *subscriberFuncCore
}

// subscriberFuncCore is the non-generic implementation of a
// SubscriberFunc. It implements the package-private subscriber
// interface so that the bus (and the subscribeState map) can store
// it without per-T itabs or dictionaries.
type subscriberFuncCore struct {
	stop       stopFlag
	unregister func()
	logf       logger.Logf
	slow       *time.Timer // used to detect slow subscriber service

	// typ is the cached reflect.Type of T. Returned by
	// subscribeType() and used by the dispatch closure to format
	// slow-subscriber log messages.
	typ reflect.Type

	// dispatchFn is the per-T dispatch closure. It performs the
	// type assertion vals.Peek().Event.(T) and runs the user
	// callback on the unboxed value. The closure body is
	// non-generic; its only per-T contribution is the type
	// assertion and the call through s.read(T), which sit inside
	// a single small captured closure rather than across a full
	// select-loop stencil per T.
	dispatchFn func(
		ctx context.Context,
		vals *queue[DeliveredEvent],
		acceptCh func() chan DeliveredEvent,
		snapshot chan chan []DeliveredEvent,
	) bool
}

func newSubscriberFunc[T any](r *subscribeState, f func(T), logf logger.Logf) *SubscriberFunc[T] {
	slow := time.NewTimer(0)
	slow.Stop() // reset in dispatch
	core := &subscriberFuncCore{
		logf: logf,
		slow: slow,
		typ:  reflect.TypeFor[T](),
	}
	core.unregister = func() { r.deleteSubscriber(core.typ) }
	core.dispatchFn = func(
		ctx context.Context,
		vals *queue[DeliveredEvent],
		acceptCh func() chan DeliveredEvent,
		snapshot chan chan []DeliveredEvent,
	) bool {
		t := vals.Peek().Event.(T)
		callDone := make(chan struct{})
		// `go runFuncCallback(f, t, callDone)` binds its arguments
		// directly to the new goroutine's frame; using a closure
		// (`go func() { f(t) }()`) would allocate a closure on the
		// heap on every dispatched event.
		go runFuncCallback(f, t, callDone)
		return dispatchFunc(ctx, dispatchFuncState{
			slow:     core.slow,
			logf:     core.logf,
			typeName: core.typ.String(),
		}, vals, acceptCh, snapshot, callDone)
	}
	return &SubscriberFunc[T]{core: core}
}

// Close closes the SubscriberFunc, indicating the caller no longer wishes to
// receive this event type.  After Close, no further events will be passed to
// the callback.
//
// If the [Bus] from which s was created is closed, s is implicitly closed and
// does not need to be closed separately.
func (s *SubscriberFunc[T]) Close() { s.core.Close() }

// Close implements the subscriber interface and the user-facing
// (*SubscriberFunc[T]).Close.
func (c *subscriberFuncCore) Close() {
	c.stop.Stop()
	c.unregister()
}

// subscribeType implements the subscriber interface.
func (c *subscriberFuncCore) subscribeType() reflect.Type { return c.typ }

// dispatch implements the subscriber interface by invoking the
// per-T dispatch closure that was captured at construction time.
func (c *subscriberFuncCore) dispatch(
	ctx context.Context,
	vals *queue[DeliveredEvent],
	acceptCh func() chan DeliveredEvent,
	snapshot chan chan []DeliveredEvent,
) bool {
	return c.dispatchFn(ctx, vals, acceptCh, snapshot)
}

// dispatchFuncState is the non-generic state needed by dispatchFunc.
// Bundling these lets us pass them as one argument and keeps the
// per-T wrapper at the dispatch call site small.
type dispatchFuncState struct {
	slow     *time.Timer
	logf     logger.Logf
	typeName string // cached reflect.TypeFor[T]().String()
}

// dispatchFunc is the non-generic body of SubscriberFunc[T].dispatch.
// It is identical in observable behavior to the original loop; the
// only differences are that the dispatched value has already been
// unboxed by the caller (and the user callback is already running
// on its own goroutine, signaling completion via callDone) and the
// type name has already been resolved (and is passed as a string).
//
// callDone is closed by runFuncCallback when the user callback returns.
func dispatchFunc(
	ctx context.Context,
	st dispatchFuncState,
	vals *queue[DeliveredEvent],
	acceptCh func() chan DeliveredEvent,
	snapshot chan chan []DeliveredEvent,
	callDone chan struct{},
) bool {
	start := time.Now()
	st.slow.Reset(slowSubscriberTimeout)
	defer st.slow.Stop()

	// Keep the cases in this select in sync with subscribeState.pump
	// above. The only difference should be that this select
	// delivers a value by calling the user callback (via the
	// goroutine spawned by the typed wrapper).
	for {
		select {
		case <-callDone:
			vals.Drop()
			return true
		case val := <-acceptCh():
			vals.Add(val)
		case <-ctx.Done():
			// Wait for the callback to be complete, but not forever.
			st.slow.Reset(5 * slowSubscriberTimeout)
			select {
			case <-st.slow.C:
				st.logf("giving up on subscriber for %s after %v at close", st.typeName, time.Since(start))
				if cibuild.On() {
					all := make([]byte, 2<<20)
					n := runtime.Stack(all, true)
					st.logf("goroutine stacks:\n%s", all[:n])
				}
			case <-callDone:
			}
			return false
		case ch := <-snapshot:
			ch <- vals.Snapshot()
		case <-st.slow.C:
			st.logf("subscriber for %s is slow (%v elapsed)", st.typeName, time.Since(start))
			st.slow.Reset(slowSubscriberTimeout)
		}
	}
}

// runFuncCallback runs f(t) and closes done when it returns. It is
// the per-T worker spawned as a goroutine for each dispatched
// event. Keeping it as a regular generic function (rather than a
// closure) means `go runFuncCallback(f, t, done)` binds its
// arguments to the goroutine's frame directly, with no per-event
// closure allocation. The body is small (defer + one indirect
// call), so the per-shape stencil cost is minimal.
func runFuncCallback[T any](f func(T), t T, done chan struct{}) {
	defer close(done)
	f(t)
}
