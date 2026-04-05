// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package watch

import (
	"sync"
	"sync/atomic"
)

// Channel is a multi-producer, multi-consumer channel that only retains
// the most recent value. Consumers are notified when a new value is sent,
// but there is no guarantee that they will observe every intermediate value.
//
// A Channel must be created with [NewChannel]. The zero value is not usable.
type Channel[T any] struct {
	state *channelState[T]
}

// channelState is the shared state for a watch channel.
type channelState[T any] struct {
	mu        sync.Mutex
	value     T
	version   uint64
	closed    atomic.Bool
	closedCh  chan struct{} // closed when the channel is closed
	receivers []*receiverState[T]
}

// receiverState is per-receiver state.
type receiverState[T any] struct {
	shared  *channelState[T]
	notify  chan struct{} // 1-buffered; poked when new value available
	version uint64        // last version seen by this receiver
	closed  atomic.Bool
}

// NewChannel creates a new watch channel with the given initial value.
// All receivers will immediately be able to read this value.
func NewChannel[T any](initial T) *Channel[T] {
	return &Channel[T]{
		state: &channelState[T]{
			value:    initial,
			version:  1,
			closedCh: make(chan struct{}),
		},
	}
}

// Sender returns a new [Sender] that can be used to send values into
// the channel. Multiple senders may be created and used concurrently.
func (c *Channel[T]) Sender() *Sender[T] {
	return &Sender[T]{shared: c.state}
}

// Receiver returns a new [Receiver] that can be used to read the most
// recent value and be notified of changes. Multiple receivers may be
// created and used concurrently.
//
// The receiver's [Receiver.Changed] channel is immediately readable,
// so the first call to [Receiver.Get] after creation will always succeed
// without blocking on Changed.
func (c *Channel[T]) Receiver() *Receiver[T] {
	rs := &receiverState[T]{
		shared:  c.state,
		notify:  make(chan struct{}, 1),
		version: 0, // behind the initial value, so first Get sees it
	}
	// Prime the notification channel so the receiver can immediately
	// detect that a value is available.
	rs.notify <- struct{}{}

	c.state.mu.Lock()
	c.state.receivers = append(c.state.receivers, rs)
	c.state.mu.Unlock()

	return &Receiver[T]{state: rs}
}

// Close closes the channel, signaling all current and future receivers
// that no more values will be sent. After Close returns, all calls to
// [Sender.Send] will panic.
//
// Close is safe to call concurrently and multiple times; only the first
// call has any effect.
func (c *Channel[T]) Close() {
	if c.state.closed.CompareAndSwap(false, true) {
		close(c.state.closedCh)
		// Wake all receivers so they can observe the close.
		c.state.mu.Lock()
		for _, rs := range c.state.receivers {
			pokeNotify(rs.notify)
		}
		c.state.mu.Unlock()
	}
}

// Sender sends values to a [Channel]. It is safe for concurrent use.
//
// A Sender holds no resources that require cleanup; it may simply be
// abandoned when no longer needed.
type Sender[T any] struct {
	shared *channelState[T]
}

// Send updates the channel's value and notifies all receivers.
// Only the most recent value is retained; intermediate values may
// be missed by receivers.
//
// Send panics if the channel has been closed.
func (s *Sender[T]) Send(value T) {
	if s.shared.closed.Load() {
		panic("watch: send on closed channel")
	}
	s.shared.mu.Lock()
	s.shared.value = value
	s.shared.version++
	for _, rs := range s.shared.receivers {
		if !rs.closed.Load() {
			pokeNotify(rs.notify)
		}
	}
	s.shared.mu.Unlock()
}

// Receiver reads values from a [Channel]. It is safe for concurrent use,
// though typical usage has a single goroutine per receiver selecting on
// [Receiver.Changed] and calling [Receiver.Get].
//
// Call [Receiver.Close] when the receiver is no longer needed, to allow
// the channel to reclaim its notification resources.
type Receiver[T any] struct {
	state *receiverState[T]
}

// Get returns the most recent value sent to the channel (or the initial
// value if no sends have occurred). It also marks the current value as
// seen, so [Changed] will not be readable again until a new value is sent.
func (r *Receiver[T]) Get() T {
	s := r.state
	s.shared.mu.Lock()
	v := s.shared.value
	s.version = s.shared.version
	s.shared.mu.Unlock()

	// Drain the notification channel since we just read the latest value.
	select {
	case <-s.notify:
	default:
	}
	return v
}

// Changed returns a channel that is readable whenever the channel contains
// a value newer than what this receiver last read via [Get]. It is intended
// to be used in a select statement.
//
// After receiving from Changed, call [Get] to retrieve the current value.
// Changed is level-triggered: it remains readable as long as there is an
// unseen value, even if multiple sends occurred since the last [Get].
func (r *Receiver[T]) Changed() <-chan struct{} {
	return r.state.notify
}

// Done returns a channel that is closed when the underlying [Channel] is
// closed. It can be used in a select statement to detect shutdown.
func (r *Receiver[T]) Done() <-chan struct{} {
	return r.state.shared.closedCh
}

// Close removes this receiver from the channel's notification list.
// After Close, the receiver should not be used.
func (r *Receiver[T]) Close() {
	s := r.state
	if s.closed.CompareAndSwap(false, true) {
		shared := s.shared
		shared.mu.Lock()
		receivers := shared.receivers
		for i, rs := range receivers {
			if rs == s {
				// Swap with last and truncate.
				receivers[i] = receivers[len(receivers)-1]
				receivers[len(receivers)-1] = nil // help GC
				shared.receivers = receivers[:len(receivers)-1]
				break
			}
		}
		shared.mu.Unlock()
	}
}

// pokeNotify performs a non-blocking send on a 1-buffered notification channel.
// If the channel already has a pending notification, this is a no-op.
func pokeNotify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
