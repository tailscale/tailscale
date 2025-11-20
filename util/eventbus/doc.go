// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package eventbus provides an in-process event bus.
//
// An event bus connects publishers of typed events with subscribers
// interested in those events. Typically, there is one global event
// bus per process.
//
// # Usage
//
// To send or receive events, first use [Bus.Client] to register with
// the bus. Clients should register with a human-readable name that
// identifies the code using the client, to aid in debugging.
//
// To publish events, use [Publish] on a Client to get a typed
// publisher for your event type, then call [Publisher.Publish] as
// needed. If your event is expensive to construct, you can optionally
// use [Publisher.ShouldPublish] to skip the work if nobody is
// listening for the event.
//
// To receive events, use [Subscribe] to get a typed subscriber for
// each event type you're interested in. Receive the events themselves
// by selecting over all your [Subscriber.Events] channels, as well as
// [Subscriber.Done] for shutdown notifications.
//
// # Concurrency properties
//
// The bus serializes all published events across all publishers, and
// preserves that ordering when delivering to subscribers that are
// attached to the same Client. In more detail:
//
//   - An event is published to the bus at some instant between the
//     start and end of the call to [Publisher.Publish].
//   - Two events cannot be published at the same instant, and so are
//     totally ordered by their publication time. Given two events E1
//     and E2, either E1 happens before E2, or E2 happens before E1.
//   - Clients dispatch events to their Subscribers in publication
//     order: if E1 happens before E2, the client always delivers E1
//     before E2.
//   - Clients do not synchronize subscriptions with each other: given
//     clients C1 and C2, both subscribed to events E1 and E2, C1 may
//     deliver both E1 and E2 before C2 delivers E1.
//
// Less formally: there is one true timeline of all published events.
// If you make a Client and subscribe to events, you will receive
// events one at a time, in the same order as the one true
// timeline. You will "skip over" events you didn't subscribe to, but
// your view of the world always moves forward in time, never
// backwards, and you will observe events in the same order as
// everyone else.
//
// However, you cannot assume that what your client see as "now" is
// the same as what other clients. They may be further behind you in
// working through the timeline, or running ahead of you. This means
// you should be careful about reaching out to another component
// directly after receiving an event, as its view of the world may not
// yet (or ever) be exactly consistent with yours.
//
// To make your code more testable and understandable, you should try
// to structure it following the actor model: you have some local
// state over which you have authority, but your only way to interact
// with state elsewhere in the program is to receive and process
// events coming from elsewhere, or to emit events of your own.
//
// # Expected subscriber behavior
//
// Subscribers are expected to promptly receive their events on
// [Subscriber.Events]. The bus has a small, fixed amount of internal
// buffering, meaning that a slow subscriber will eventually cause
// backpressure and block publication of all further events.
//
// In general, you should receive from your subscriber(s) in a loop,
// and only do fast state updates within that loop. Any heavier work
// should be offloaded to another goroutine.
//
// Causing publishers to block from backpressure is considered a bug
// in the slow subscriber causing the backpressure, and should be
// addressed there. Publishers should assume that Publish will not
// block for extended periods of time, and should not make exceptional
// effort to behave gracefully if they do get blocked.
//
// These blocking semantics are provisional and subject to
// change. Please speak up if this causes development pain, so that we
// can adapt the semantics to better suit our needs.
//
// # Debugging facilities
//
// The [Debugger], obtained through [Bus.Debugger], provides
// introspection facilities to monitor events flowing through the bus,
// and inspect publisher and subscriber state.
//
// Additionally, a debug command exists for monitoring the eventbus:
//
//	tailscale debug daemon-bus-events
//
// # Testing facilities
//
// Helpers for testing code with the eventbus can be found in:
//
//	eventbus/eventbustest
package eventbus
