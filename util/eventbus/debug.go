// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package eventbus

import (
	"cmp"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/syncs"
	"tailscale.com/types/logger"
)

// slowSubscriberTimeout is a timeout after which a subscriber that does not
// accept a pending event will be flagged as being slow.
const slowSubscriberTimeout = 5 * time.Second

// A Debugger offers access to a bus's privileged introspection and
// debugging facilities.
//
// The debugger's functionality is intended for humans and their tools
// to examine and troubleshoot bus clients, and should not be used in
// normal codepaths.
//
// In particular, the debugger provides access to information that is
// deliberately withheld from bus clients to encourage more robust and
// maintainable code - for example, the sender of an event, or the
// event streams of other clients. Please don't use the debugger to
// circumvent these restrictions for purposes other than debugging.
type Debugger struct {
	bus *Bus
}

// Clients returns a list of all clients attached to the bus.
func (d *Debugger) Clients() []*Client {
	ret := d.bus.listClients()
	slices.SortFunc(ret, func(a, b *Client) int {
		return cmp.Compare(a.Name(), b.Name())
	})
	return ret
}

// PublishQueue returns the contents of the publish queue.
//
// The publish queue contains events that have been accepted by the
// bus from Publish() calls, but have not yet been routed to relevant
// subscribers.
//
// This queue is expected to be almost empty in normal operation. A
// full publish queue indicates that a slow subscriber downstream is
// causing backpressure and stalling the bus.
func (d *Debugger) PublishQueue() []PublishedEvent {
	return d.bus.snapshotPublishQueue()
}

// checkClient verifies that client is attached to the same bus as the
// Debugger, and panics if not.
func (d *Debugger) checkClient(client *Client) {
	if client.bus != d.bus {
		panic(fmt.Errorf("SubscribeQueue given client belonging to wrong bus"))
	}
}

// SubscribeQueue returns the contents of the given client's subscribe
// queue.
//
// The subscribe queue contains events that are to be delivered to the
// client, but haven't yet been handed off to the relevant
// [Subscriber].
//
// This queue is expected to be almost empty in normal operation. A
// full subscribe queue indicates that the client is accepting events
// too slowly, and may be causing the rest of the bus to stall.
func (d *Debugger) SubscribeQueue(client *Client) []DeliveredEvent {
	d.checkClient(client)
	return client.snapshotSubscribeQueue()
}

// WatchBus streams information about all events passing through the
// bus.
//
// Monitored events are delivered in the bus's global publication
// order (see "Concurrency properties" in the package docs).
//
// The caller must consume monitoring events promptly to avoid
// stalling the bus (see "Expected subscriber behavior" in the package
// docs).
func (d *Debugger) WatchBus() *Subscriber[RoutedEvent] {
	return newMonitor(d.bus.routeDebug.add)
}

// WatchPublish streams information about all events published by the
// given client.
//
// Monitored events are delivered in the bus's global publication
// order (see "Concurrency properties" in the package docs).
//
// The caller must consume monitoring events promptly to avoid
// stalling the bus (see "Expected subscriber behavior" in the package
// docs).
func (d *Debugger) WatchPublish(client *Client) *Subscriber[PublishedEvent] {
	d.checkClient(client)
	return newMonitor(client.publishDebug.add)
}

// WatchSubscribe streams information about all events received by the
// given client.
//
// Monitored events are delivered in the bus's global publication
// order (see "Concurrency properties" in the package docs).
//
// The caller must consume monitoring events promptly to avoid
// stalling the bus (see "Expected subscriber behavior" in the package
// docs).
func (d *Debugger) WatchSubscribe(client *Client) *Subscriber[DeliveredEvent] {
	d.checkClient(client)
	return newMonitor(client.subscribeState().debug.add)
}

// PublishTypes returns the list of types being published by client.
//
// The returned types are those for which the client has obtained a
// [Publisher]. The client may not have ever sent the type in
// question.
func (d *Debugger) PublishTypes(client *Client) []reflect.Type {
	d.checkClient(client)
	return client.publishTypes()
}

// SubscribeTypes returns the list of types being subscribed to by
// client.
//
// The returned types are those for which the client has obtained a
// [Subscriber]. The client may not have ever received the type in
// question, and here may not be any publishers of the type.
func (d *Debugger) SubscribeTypes(client *Client) []reflect.Type {
	d.checkClient(client)
	return client.subscribeTypes()
}

// A hook collects hook functions that can be run as a group.
type hook[T any] struct {
	syncs.Mutex
	fns []hookFn[T]
}

var hookID atomic.Uint64

// add registers fn to be called when the hook is run. Returns an
// unregistration function that removes fn from the hook when called.
func (h *hook[T]) add(fn func(T)) (remove func()) {
	id := hookID.Add(1)
	h.Lock()
	defer h.Unlock()
	h.fns = append(h.fns, hookFn[T]{id, fn})
	return func() { h.remove(id) }
}

// remove removes the function with the given ID from the hook.
func (h *hook[T]) remove(id uint64) {
	h.Lock()
	defer h.Unlock()
	h.fns = slices.DeleteFunc(h.fns, func(f hookFn[T]) bool { return f.ID == id })
}

// active reports whether any functions are registered with the
// hook. This can be used to skip expensive work when the hook is
// inactive.
func (h *hook[T]) active() bool {
	h.Lock()
	defer h.Unlock()
	return len(h.fns) > 0
}

// run calls all registered functions with the value v.
func (h *hook[T]) run(v T) {
	h.Lock()
	defer h.Unlock()
	for _, fn := range h.fns {
		fn.Fn(v)
	}
}

type hookFn[T any] struct {
	ID uint64
	Fn func(T)
}

// DebugEvent is a representation of an event used for debug clients.
type DebugEvent struct {
	Count int
	Type  string
	From  string
	To    []string
	Event any
}

// DebugTopics provides the JSON encoding as a wrapper for a collection of [DebugTopic].
type DebugTopics struct {
	Topics []DebugTopic
}

// DebugTopic provides the JSON encoding of publishers and subscribers for a
// given topic.
type DebugTopic struct {
	Name        string
	Publisher   string
	Subscribers []string
}

// logfForCaller returns a [logger.Logf] that prefixes its output with the
// package, filename, and line number of the caller's caller.
// If logf == nil, it returns [logger.Discard].
// If the caller location could not be determined, it returns logf unmodified.
func logfForCaller(logf logger.Logf) logger.Logf {
	if logf == nil {
		return logger.Discard
	}
	pc, fpath, line, _ := runtime.Caller(2) // +1 for my caller, +1 for theirs
	if f := runtime.FuncForPC(pc); f != nil {
		return logger.WithPrefix(logf, fmt.Sprintf("%s %s:%d: ", funcPackageName(f.Name()), filepath.Base(fpath), line))
	}
	return logf
}

func funcPackageName(funcName string) string {
	ls := max(strings.LastIndex(funcName, "/"), 0)
	for {
		i := strings.LastIndex(funcName, ".")
		if i <= ls {
			return funcName
		}
		funcName = funcName[:i]
	}
}
