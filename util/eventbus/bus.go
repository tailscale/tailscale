// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"context"
	"reflect"
	"slices"
	"sync"

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

	topicsMu sync.Mutex
	topics   map[reflect.Type][]*subscribeState

	// Used for introspection/debugging only, not in the normal event
	// publishing path.
	clientsMu sync.Mutex
	clients   set.Set[*Client]
}

// New returns a new bus. Use [Publish] to make event publishers,
// and [Subscribe] and [SubscribeFunc] to make event subscribers.
func New() *Bus {
	ret := &Bus{
		write:    make(chan PublishedEvent),
		snapshot: make(chan chan []PublishedEvent),
		topics:   map[reflect.Type][]*subscribeState{},
		clients:  set.Set[*Client]{},
	}
	ret.router = runWorker(ret.pump)
	return ret
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
	var vals queue[PublishedEvent]
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
			dests := b.dest(reflect.ValueOf(val.Event).Type())

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
	defer b.topicsMu.Unlock()
	b.topics[t] = append(b.topics[t], q)
	return func() {
		b.unsubscribe(t, q)
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
	mu             sync.Mutex
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
