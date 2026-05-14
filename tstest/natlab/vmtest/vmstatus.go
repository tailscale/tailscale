// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"fmt"
	"sync"
	"time"
)

// StepStatus is the state of a declared test step.
type StepStatus int

const (
	StepPending StepStatus = iota // not yet started
	StepRunning                   // Begin called
	StepDone                      // End(nil) called
	StepFailed                    // End(non-nil) called
)

func (s StepStatus) String() string {
	switch s {
	case StepPending:
		return "pending"
	case StepRunning:
		return "running"
	case StepDone:
		return "done"
	case StepFailed:
		return "failed"
	}
	return fmt.Sprintf("StepStatus(%d)", int(s))
}

// Icon returns a Unicode icon for the step status.
func (s StepStatus) Icon() string {
	switch s {
	case StepPending:
		return "○"
	case StepRunning:
		return "◉"
	case StepDone:
		return "✓"
	case StepFailed:
		return "✗"
	}
	return "?"
}

// Step is a declared stage of a test, created by [Env.AddStep].
// The web UI shows all steps from the start, tracking their progress.
type Step struct {
	mu      sync.Mutex
	name    string
	index   int // 0-based position in Env.steps
	env     *Env
	status  StepStatus
	err     error
	started time.Time
	ended   time.Time
}

// Name returns the step's display name.
func (s *Step) Name() string { return s.name }

// Index returns the step's 0-based position.
func (s *Step) Index() int { return s.index }

// Status returns the current status.
func (s *Step) Status() StepStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Err returns the error if the step failed, or nil.
func (s *Step) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Elapsed returns how long the step has been running (if running)
// or how long it took (if done/failed). Returns 0 if pending.
func (s *Step) Elapsed() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started.IsZero() {
		return 0
	}
	if !s.ended.IsZero() {
		return s.ended.Sub(s.started)
	}
	return time.Since(s.started)
}

// Begin marks the step as running. Publishes an event to the web UI.
func (s *Step) Begin() {
	s.mu.Lock()
	if s.status != StepPending {
		s.mu.Unlock()
		panic(fmt.Sprintf("Step %q: Begin called in state %s", s.name, s.status))
	}
	s.started = time.Now()
	s.status = StepRunning
	s.mu.Unlock()
	s.env.publishStepChange(s)
}

// End marks the step as done (err == nil) or failed (err != nil).
// It publishes a status change event to the web UI.
// It does not call t.Fatalf; callers should handle the error as appropriate
// (return it from errgroup, call t.Fatalf on the test goroutine, etc).
func (s *Step) End(err error) {
	s.mu.Lock()
	if s.status != StepRunning {
		s.mu.Unlock()
		panic(fmt.Sprintf("Step %q: End called in state %s", s.name, s.status))
	}
	s.ended = time.Now()
	if err != nil {
		s.status = StepFailed
		s.err = err
	} else {
		s.status = StepDone
	}
	s.mu.Unlock()
	s.env.publishStepChange(s)
}

// Fatalf marks the step as failed (as [Step.End]), and then logs a test
// failure to the environment's test, with an error constructed from the given
// arguments.
func (s *Step) Fatalf(msg string, args ...any) {
	s.Fatal(fmt.Errorf(msg, args...))
}

// Fatal marks the step as failed (as [Step.End]), and then logs a test failure
// to the environment's test, with the specified (non-nil) error. It will panic
// if err == nil.
func (s *Step) Fatal(err error) {
	if err == nil {
		panic(fmt.Sprintf("Step %q: Fatal called with a nil error", s.name))
	}
	s.End(err)
	s.env.t.Fatal(err)
}

// EventType identifies the kind of event published to the EventBus.
type EventType string

const (
	EventStepChanged   EventType = "step_changed"   // a Step changed status
	EventConsoleOutput EventType = "console_output" // serial console line
	EventDHCPDiscover  EventType = "dhcp_discover"  // VM sent DHCP Discover
	EventDHCPOffer     EventType = "dhcp_offer"     // server sent DHCP Offer
	EventDHCPRequest   EventType = "dhcp_request"   // VM sent DHCP Request
	EventDHCPAck       EventType = "dhcp_ack"       // server sent DHCP Ack
	EventScreenshot    EventType = "screenshot"     // VM display screenshot (JPEG, base64)
	EventTailscale     EventType = "tailscale"      // Tailscale status change
	EventTestStatus    EventType = "test_status"    // test Running/Passed/Failed
)

// TestStatus tracks whether the overall test is running, passed, or failed.
type TestStatus struct {
	mu      sync.Mutex
	state   string // "Running", "Passed", "Failed"
	started time.Time
	ended   time.Time
}

func newTestStatus() *TestStatus {
	return &TestStatus{state: "Running", started: time.Now()}
}

// State returns the current test state.
func (ts *TestStatus) State() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.state
}

// Elapsed returns total test duration.
func (ts *TestStatus) Elapsed() time.Duration {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if !ts.ended.IsZero() {
		return ts.ended.Sub(ts.started)
	}
	return time.Since(ts.started)
}

// StartUnixMilli returns the test start time as Unix milliseconds,
// for the client-side elapsed timer.
func (ts *TestStatus) StartUnixMilli() int64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.started.UnixMilli()
}

// finish marks the test as passed or failed.
func (ts *TestStatus) finish(failed bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.ended = time.Now()
	if failed {
		ts.state = "Failed"
	} else {
		ts.state = "Passed"
	}
}

// VMEvent is a single event published to the [EventBus].
type VMEvent struct {
	Time     time.Time
	NodeName string // "" for global events
	Type     EventType
	Message  string // human-readable description
	Detail   string // e.g. IP address, node key
	Step     *Step  // non-nil for EventStepChanged
	NIC      int    // NIC index for DHCP events (0-based); -1 if not applicable
}

// NICStatus is the DHCP state for one NIC on a node.
type NICStatus struct {
	NetName string // human label like "192.168.1.0/24" or "10.0.0.0/24"
	DHCP    string // "waiting", "Discover sent", "Got 10.0.0.101", etc.
}

// NodeStatus tracks the current DHCP and Tailscale state of a VM node
// for rendering on the web UI's initial page load.
type NodeStatus struct {
	Name           string
	OS             string
	NICs           []NICStatus // one per NIC; index matches NIC index
	JoinsTailnet   bool        // whether this node runs Tailscale
	Tailscale      string      // "--", "Up (100.64.0.1)", etc.
	Console        []string    // recent console output lines (ring buffer)
	Screenshot     string      // latest screenshot as data URI, or ""
	ScreenshotPort int         // Host.app screenshot server port, or 0
}

const maxConsoleLines = 200

const (
	eventBusHistorySize   = 500
	subscriberChannelSize = 1000
)

// EventBus broadcasts VMEvents to subscribers and keeps a history for
// late joiners. It is safe for concurrent use.
type EventBus struct {
	mu          sync.Mutex
	history     []VMEvent
	subscribers map[*subscriber]struct{}
}

func newEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[*subscriber]struct{}),
	}
}

// Publish sends an event to all subscribers and appends it to the history.
// Non-blocking: slow subscribers are skipped.
func (b *EventBus) Publish(ev VMEvent) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Don't store screenshots in history — they're large and only the
	// latest one matters (stored in NodeStatus.Screenshot instead).
	if ev.Type != EventScreenshot {
		b.history = append(b.history, ev)
	}
	if len(b.history) > eventBusHistorySize {
		// Trim old events.
		copy(b.history, b.history[len(b.history)-eventBusHistorySize:])
		b.history = b.history[:eventBusHistorySize]
	}
	for sub := range b.subscribers {
		select {
		case sub.ch <- ev:
		default:
			// Slow consumer, skip.
		}
	}
}

// Subscribe returns a new subscriber that receives the event history
// followed by live events.
func (b *EventBus) Subscribe() *subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	sub := &subscriber{
		bus:  b,
		ch:   make(chan VMEvent, subscriberChannelSize),
		done: make(chan struct{}),
	}
	// Send history.
	for _, ev := range b.history {
		select {
		case sub.ch <- ev:
		default:
		}
	}
	b.subscribers[sub] = struct{}{}
	return sub
}

func (b *EventBus) unsubscribe(sub *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subscribers, sub)
}

// subscriber receives events from an [EventBus].
type subscriber struct {
	bus  *EventBus
	ch   chan VMEvent
	done chan struct{}
	once sync.Once
}

// Events returns the channel of events. Closed when Close is called.
func (s *subscriber) Events() <-chan VMEvent {
	return s.ch
}

// Close unsubscribes and closes the event channel.
func (s *subscriber) Close() {
	s.once.Do(func() {
		if s.bus != nil {
			s.bus.unsubscribe(s)
		}
		close(s.done)
	})
}

// Done returns a channel that's closed when Close is called.
func (s *subscriber) Done() <-chan struct{} {
	return s.done
}
