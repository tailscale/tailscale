// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"slices"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

type PublishedEvent struct {
	Event any
	From  *Client
}

type RoutedEvent struct {
	Event any
	From  *Client
	To    []*Client
}

// Bus is an event bus that distributes published events to interested
// subscribers.
type Bus struct {
	router     *worker
	write      chan PublishedEvent
	snapshot   chan chan []PublishedEvent
	routeDebug hook[RoutedEvent]
	logf       logger.Logf

	topicsMu syncs.Mutex
	topics   map[reflect.Type][]*subscribeState
	// pubs records, for each event type, the clients that hold publishers
	// for it and how many. It is used only to detect publisher/subscriber
	// type mismatches when a publisher or subscriber is registered.
	pubs map[reflect.Type]map[*Client]int

	// Used for introspection/debugging only, not in the normal event
	// publishing path.
	clientsMu syncs.Mutex
	clients   set.Set[*Client]
}

// New returns a new bus with default options. It is equivalent to
// calling [NewWithOptions] with zero [BusOptions].
func New() *Bus { return NewWithOptions(BusOptions{}) }

// NewWithOptions returns a new [Bus] with the specified [BusOptions].
// Use [Bus.Client] to construct clients on the bus.
// Use [Publish] to make event publishers.
// Use [Subscribe] and [SubscribeFunc] to make event subscribers.
func NewWithOptions(opts BusOptions) *Bus {
	ret := &Bus{
		write:    make(chan PublishedEvent),
		snapshot: make(chan chan []PublishedEvent),
		topics:   map[reflect.Type][]*subscribeState{},
		pubs:     map[reflect.Type]map[*Client]int{},
		clients:  set.Set[*Client]{},
		logf:     opts.logger(),
	}
	ret.router = runWorker(ret.pump)
	return ret
}

// BusOptions are optional parameters for a [Bus]. A zero value is ready for
// use and provides defaults as described.
type BusOptions struct {
	// Logf, if non-nil, is used for debug logs emitted by the bus and clients,
	// publishers, and subscribers under its care. If it is nil, logs are sent
	// to [log.Printf].
	Logf logger.Logf
}

func (o BusOptions) logger() logger.Logf {
	if o.Logf == nil {
		return log.Printf
	}
	return o.Logf
}

// Client returns a new client with no subscriptions. Use [Subscribe]
// to receive events, and [Publish] to emit events.
//
// The client's name is used only for debugging, to tell humans what
// piece of code a publisher/subscriber belongs to. Aim for something
// short but unique, for example "kernel-route-monitor" or "taildrop",
// not "watcher".
func (b *Bus) Client(name string) *Client {
	ret := &Client{
		name: name,
		bus:  b,
		pub:  set.Set[publisher]{},
	}
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	b.clients.Add(ret)
	return ret
}

// Debugger returns the debugging facility for the bus.
func (b *Bus) Debugger() *Debugger {
	return &Debugger{b}
}

// ProbeLocks acquires and releases the bus's internal mutexes.
func (b *Bus) ProbeLocks() {
	b.topicsMu.Lock()
	b.topicsMu.Unlock()

	b.clientsMu.Lock()
	b.clientsMu.Unlock()
}

// Close closes the bus. It implicitly closes all clients, publishers and
// subscribers attached to the bus.
//
// Close blocks until the bus is fully shut down. The bus is
// permanently unusable after closing.
func (b *Bus) Close() {
	b.router.StopAndWait()

	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	for c := range b.clients {
		c.Close()
	}
	b.clients = nil
}

func (b *Bus) pump(ctx context.Context) {
	// Limit how many published events we can buffer in the PublishedEvent queue.
	//
	// Subscribers have unbounded DeliveredEvent queues (see tailscale/tailscale#18020),
	// so this queue doesn't need to be unbounded. Keeping it bounded may also help
	// catch cases where subscribers stop pumping events completely, such as due to a bug
	// in [subscribeState.pump], [Subscriber.dispatch], or [SubscriberFunc.dispatch]).
	const maxPublishedEvents = 16
	vals := queue[PublishedEvent]{capacity: maxPublishedEvents}
	acceptCh := func() chan PublishedEvent {
		if vals.Full() {
			return nil
		}
		return b.write
	}
	for {
		// Drain all pending events. Note that while we're draining
		// events into subscriber queues, we continue to
		// opportunistically accept more incoming events, if we have
		// queue space for it.
		for !vals.Empty() {
			val := vals.Peek()
			dests := b.dest(reflect.TypeOf(val.Event))

			if b.routeDebug.active() {
				clients := make([]*Client, len(dests))
				for i := range len(dests) {
					clients[i] = dests[i].client
				}
				b.routeDebug.run(RoutedEvent{
					Event: val.Event,
					From:  val.From,
					To:    clients,
				})
			}

			for _, d := range dests {
				evt := DeliveredEvent{
					Event: val.Event,
					From:  val.From,
					To:    d.client,
				}
			deliverOne:
				for {
					select {
					case d.write <- evt:
						break deliverOne
					case <-d.closed():
						// Queue closed, don't block but continue
						// delivering to others.
						break deliverOne
					case in := <-acceptCh():
						vals.Add(in)
						in.From.publishDebug.run(in)
					case <-ctx.Done():
						return
					case ch := <-b.snapshot:
						ch <- vals.Snapshot()
					}
				}
			}
			vals.Drop()
		}

		// Inbound queue empty, wait for at least 1 work item before
		// resuming.
		for vals.Empty() {
			select {
			case <-ctx.Done():
				return
			case in := <-b.write:
				vals.Add(in)
				in.From.publishDebug.run(in)
			case ch := <-b.snapshot:
				ch <- nil
			}
		}
	}
}

// logger returns a [logger.Logf] to which logs related to bus activity should be written.
func (b *Bus) logger() logger.Logf { return b.logf }

func (b *Bus) dest(t reflect.Type) []*subscribeState {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	return b.topics[t]
}

func (b *Bus) shouldPublish(t reflect.Type) bool {
	if b.routeDebug.active() {
		return true
	}

	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	return len(b.topics[t]) > 0
}

func (b *Bus) listClients() []*Client {
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	return b.clients.Slice()
}

func (b *Bus) snapshotPublishQueue() []PublishedEvent {
	resp := make(chan []PublishedEvent)
	select {
	case b.snapshot <- resp:
		return <-resp
	case <-b.router.Done():
		return nil
	}
}

func (b *Bus) subscribe(t reflect.Type, q *subscribeState) (cancel func()) {
	b.topicsMu.Lock()
	b.topics[t] = append(b.topics[t], q)
	warning := b.mismatchWarningLocked(t, q.client, false)
	b.topicsMu.Unlock()
	if warning != "" {
		b.logf("%s", warning)
	}
	return func() {
		b.unsubscribe(t, q)
	}
}

func (b *Bus) addPublisher(t reflect.Type, c *Client) {
	b.topicsMu.Lock()
	clients := b.pubs[t]
	if clients == nil {
		clients = map[*Client]int{}
		b.pubs[t] = clients
	}
	clients[c]++
	warning := b.mismatchWarningLocked(t, c, true)
	b.topicsMu.Unlock()
	if warning != "" {
		b.logf("%s", warning)
	}
}

func (b *Bus) deletePublisher(t reflect.Type, c *Client) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	clients := b.pubs[t]
	if clients[c]--; clients[c] <= 0 {
		delete(clients, c)
	}
	if len(clients) == 0 {
		delete(b.pubs, t)
	}
}

// mismatchWarningLocked returns a warning to log if client c has just
// registered a publisher (if pub is true) or subscriber of type t, and
// the other side has registrations for the pointer or non-pointer
// counterpart of t. Events are routed by exact type, so such pairs
// typically indicate a bug.
//
// It returns "" if there is no mismatch.
func (b *Bus) mismatchWarningLocked(t reflect.Type, c *Client, pub bool) string {
	sib := siblingType(t)
	if sib == nil {
		return ""
	}
	var pubType, subType reflect.Type
	var pubNames, subNames []string
	if pub {
		pubType, subType = t, sib
		for _, s := range b.topics[sib] {
			subNames = append(subNames, s.client.Name())
		}
		slices.Sort(subNames)
		pubNames = []string{c.Name()}
	} else {
		pubType, subType = sib, t
		for pc := range b.pubs[sib] {
			pubNames = append(pubNames, pc.Name())
		}
		slices.Sort(pubNames)
		subNames = []string{c.Name()}
	}
	if len(pubNames) == 0 || len(subNames) == 0 {
		return ""
	}
	return fmt.Sprintf("[unexpected] eventbus: %q publish %v, but %q subscribe to %v",
		pubNames, pubType, subNames, subType)
}

// siblingType returns *t if t is not a pointer type,
// or the type t points to if it is.
// It returns nil if t is nil.
func siblingType(t reflect.Type) reflect.Type {
	switch {
	case t == nil:
		return nil
	case t.Kind() == reflect.Pointer:
		return t.Elem()
	default:
		return reflect.PointerTo(t)
	}
}

func (b *Bus) unsubscribe(t reflect.Type, q *subscribeState) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	// Topic slices are accessed by pump without holding a lock, so we
	// have to replace the entire slice when unsubscribing.
	// Unsubscribing should be infrequent enough that this won't
	// matter.
	i := slices.Index(b.topics[t], q)
	if i < 0 {
		return
	}
	b.topics[t] = slices.Delete(slices.Clone(b.topics[t]), i, i+1)
}

// A worker runs a worker goroutine and helps coordinate its shutdown.
type worker struct {
	ctx     context.Context
	stop    context.CancelFunc
	stopped chan struct{}
}

// runWorker creates a worker goroutine running fn. The context passed
// to fn is canceled by [worker.Stop].
func runWorker(fn func(context.Context)) *worker {
	ctx, stop := context.WithCancel(context.Background())
	ret := &worker{
		ctx:     ctx,
		stop:    stop,
		stopped: make(chan struct{}),
	}
	go ret.run(fn)
	return ret
}

func (w *worker) run(fn func(context.Context)) {
	defer close(w.stopped)
	fn(w.ctx)
}

// Stop signals the worker goroutine to shut down.
func (w *worker) Stop() { w.stop() }

// Done returns a channel that is closed when the worker goroutine
// exits.
func (w *worker) Done() <-chan struct{} { return w.stopped }

// Wait waits until the worker goroutine has exited.
func (w *worker) Wait() { <-w.stopped }

// StopAndWait signals the worker goroutine to shut down, then waits
// for it to exit.
func (w *worker) StopAndWait() {
	w.stop()
	<-w.stopped
}

// stopFlag is a value that can be watched for a notification. The
// zero value is ready for use.
//
// The flag is notified by running [stopFlag.Stop]. Stop can be called
// multiple times. Upon the first call to Stop, [stopFlag.Done] is
// closed, all pending [stopFlag.Wait] calls return, and future Wait
// calls return immediately.
//
// A stopFlag can only notify once, and is intended for use as a
// one-way shutdown signal that's lighter than a cancellable
// context.Context.
type stopFlag struct {
	// guards the lazy construction of stopped, and the value of
	// alreadyStopped.
	mu             syncs.Mutex
	stopped        chan struct{}
	alreadyStopped bool
}

func (s *stopFlag) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alreadyStopped {
		return
	}
	s.alreadyStopped = true
	if s.stopped == nil {
		s.stopped = make(chan struct{})
	}
	close(s.stopped)
}

func (s *stopFlag) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped == nil {
		s.stopped = make(chan struct{})
	}
	return s.stopped
}

func (s *stopFlag) Wait() {
	<-s.Done()
}
