package eventbus

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type publishedEvent struct {
	Event     any
	From      *Client
	Published time.Time
}

type routedEvent struct {
	Event any
	From  *Client   // publisher's name
	To    []*Client // target names

	Published          time.Time
	ReachedRouter      time.Time
	DestinationsPicked time.Time
}

type subscribedEvent struct {
	Event any
	From  *Client
	To    *Client

	Published          time.Time
	ReachedRouter      time.Time
	DestinationsPicked time.Time
	QueuedAtSubscriber time.Time
	NextToDeliver      time.Time
}

// A hook is a hook point to which functions can be attached.  When
// the hook is run, attached callbacks are invoked synchronously, in
// the order they were added.
type hook[T any] struct {
	sync.Mutex
	fns []hookFn[T]
}

// add registers fn to be called when the hook is run.
//
// Returns a cleanup function that unregisters fn when called.
func (h *hook[T]) add(fn func(T)) (remove func()) {
	id := hookID.Add(1)
	h.Lock()
	defer h.Unlock()
	h.fns = append(h.fns, hookFn[T]{id, fn})
	return func() { h.remove(id) }
}

// remove unregisters the hook function with the given ID.
func (h *hook[T]) remove(id uint64) {
	h.Lock()
	defer h.Unlock()
	h.fns = slices.DeleteFunc(h.fns, func(f hookFn[T]) bool { return f.ID == id })
}

// run calls all registered hooks functions with v.
func (h *hook[T]) run(v T) {
	h.Lock()
	defer h.Unlock()
	for _, f := range h.fns {
		f.run(v)
	}
}

// active reports whether any hook functions are registered. Hook call
// sites can use this to skip doing work if nobody's listening.
func (h *hook[T]) active() bool {
	h.Lock()
	defer h.Unlock()
	return len(h.fns) > 0
}

var hookID atomic.Uint64

// hookFn attaches a comparable ID to a hook function, so that hooks
// can be found and deleted during cleanup.
type hookFn[T any] struct {
	ID uint64
	Fn func(T)
}

func (h hookFn[T]) run(v T) { h.Fn(v) }
