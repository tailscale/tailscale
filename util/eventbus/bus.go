// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"reflect"
	"sync"

	"tailscale.com/util/set"
)

// Bus is an event bus that distributes published events to interested
// subscribers.
type Bus struct {
	write chan any
	stop  chan struct{}
	dump  chan chan []any

	topicsMu sync.Mutex // guards everything below.
	topics   map[reflect.Type][]*Queue

	// Used for introspection/debugging only, not in the normal event
	// publishing path.
	publishers set.Set[publisher]
	queues     set.Set[*Queue]
}

// New returns a new bus. Use [PublisherOf] to make event publishers,
// and [Bus.Queue] and [Subscribe] to make event subscribers.
func New() *Bus {
	ret := &Bus{
		topics:     map[reflect.Type][]*Queue{},
		publishers: set.Set[publisher]{},
		queues:     set.Set[*Queue]{},
	}
	go ret.pump()
	return ret
}

func (b *Bus) pump() {
	var vals queue
	for {
		for !vals.Empty() {
			val := vals.Peek()
			dests := b.dest(reflect.ValueOf(val).Type())
			for _, d := range dests {
			deliverOne:
				for {
					select {
					case d.write <- val:
						break deliverOne
					case <-d.stop:
						// Queue closed, don't block.
						break deliverOne
					case <-b.stop:
						return
					case ch := <-b.dump:
						ch <- vals.Dump()
					}
				}
			}
			vals.Drop()
		}

		for !vals.Full() {
			select {
			case <-b.stop:
				return
			case val := <-b.write:
				vals.Add(val)
			case ch := <-b.dump:
				ch <- vals.Dump()
			}
		}
	}
}

func (b *Bus) dest(t reflect.Type) []*Queue {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	return b.topics[t]
}

func (b *Bus) subscribe(t reflect.Type, q *Queue) (cancel func()) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	b.topics[t] = append(b.topics[t], q)
	return func() {
		b.unsubscribe(t, q)
	}
}

func (b *Bus) unsubscribe(t reflect.Type, q *Queue) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	// Topic slices are accessed by pump without holding a lock, so we
	// have to replace the entire slice when
	// unsubscribing. Unsubscribing should be infrequent enough that
	// this won't matter.
	subs := make([]*Queue, 0, len(b.topics[t])-1)
	for _, s := range subs {
		if s == q {
			continue
		}
		subs = append(subs, s)
	}
	b.topics[t] = subs
}

// Queue returns a new queue with no subscriptions. Use [Subscribe] to
// atach subscriptions to it.
//
// The queue's name should be a short, human-readable string that
// identifies this queue. The name is only visible through debugging
// APIs.
func (b *Bus) Queue(name string) *Queue {
	return newQueue(b, name)
}

func (b *Bus) addQueue(q *Queue) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	b.queues.Add(q)
}

func (b *Bus) deleteQueue(q *Queue) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	b.queues.Delete(q)
}

func (b *Bus) addPublisher(p publisher) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	b.publishers.Add(p)
}

func (b *Bus) deletePublisher(p publisher) {
	b.topicsMu.Lock()
	defer b.topicsMu.Unlock()
	b.publishers.Delete(p)
}
