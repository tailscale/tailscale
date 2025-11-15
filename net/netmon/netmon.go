// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package monitor provides facilities for monitoring network
// interface and route changes. It primarily exists to know when
// portable devices move between different networks.
package netmon

import (
	"encoding/json"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
)

// pollWallTimeInterval is how often we check the time to check
// for big jumps in wall (non-monotonic) time as a backup mechanism
// to get notified of a sleeping device waking back up.
// Usually there are also minor network change events on wake that let
// us check the wall time sooner than this.
const pollWallTimeInterval = 15 * time.Second

// message represents a message returned from an osMon.
type message interface {
	// Ignore is whether we should ignore this message.
	ignore() bool
}

// osMon is the interface that each operating system-specific
// implementation of the link monitor must implement.
type osMon interface {
	Close() error

	// Receive returns a new network interface change message. It
	// should block until there's either something to return, or
	// until the osMon is closed. After a Close, the returned
	// error is ignored.
	Receive() (message, error)

	// IsInterestingInterface reports whether the provided interface should
	// be considered for network change events.
	IsInterestingInterface(iface string) bool
}

// Monitor represents a monitoring instance.
type Monitor struct {
	logf    logger.Logf
	b       *eventbus.Client
	changed *eventbus.Publisher[ChangeDelta]

	om     osMon         // nil means not supported on this platform
	change chan bool     // send false to wake poller, true to also force ChangeDeltas be sent
	stop   chan struct{} // closed on Stop
	static bool          // static Monitor that doesn't actually monitor

	// Things that must be set early, before use,
	// and not change at runtime.
	tsIfName string // tailscale interface name, if known/set ("tailscale0", "utun3", ...)

	mu         syncs.Mutex // guards all following fields
	cbs        set.HandleSet[ChangeFunc]
	ifState    *State
	gwValid    bool       // whether gw and gwSelfIP are valid
	gw         netip.Addr // our gateway's IP
	gwSelfIP   netip.Addr // our own IP address (that corresponds to gw)
	started    bool
	closed     bool
	goroutines sync.WaitGroup
	wallTimer  *time.Timer // nil until Started; re-armed AfterFunc per tick
	lastWall   time.Time
	timeJumped bool // whether we need to send a changed=true after a big time jump
}

// ChangeFunc is a callback function registered with Monitor that's called when the
// network changed.
type ChangeFunc func(*ChangeDelta)

// ChangeDelta describes the difference between two network states.
type ChangeDelta struct {
	// Old is the old interface state, if known.
	// It's nil if the old state is unknown.
	// Do not mutate it.
	Old *State

	// New is the new network state.
	// It is always non-nil.
	// Do not mutate it.
	New *State

	// Major is our legacy boolean of whether the network changed in some major
	// way.
	//
	// Deprecated: do not remove. As of 2023-08-23 we're in a renewed effort to
	// remove it and ask specific qustions of ChangeDelta instead. Look at Old
	// and New (or add methods to ChangeDelta) instead of using Major.
	Major bool

	// TimeJumped is whether there was a big jump in wall time since the last
	// time we checked. This is a hint that a mobile sleeping device might have
	// come out of sleep.
	TimeJumped bool

	// TODO(bradfitz): add some lazy cached fields here as needed with methods
	// on *ChangeDelta to let callers ask specific questions
}

// New instantiates and starts a monitoring instance.
// The returned monitor is inactive until it's started by the Start method.
// Use RegisterChangeCallback to get notified of network changes.
func New(bus *eventbus.Bus, logf logger.Logf) (*Monitor, error) {
	logf = logger.WithPrefix(logf, "monitor: ")
	m := &Monitor{
		logf:     logf,
		b:        bus.Client("netmon"),
		change:   make(chan bool, 1),
		stop:     make(chan struct{}),
		lastWall: wallTime(),
	}
	m.changed = eventbus.Publish[ChangeDelta](m.b)
	st, err := m.interfaceStateUncached()
	if err != nil {
		return nil, err
	}
	m.ifState = st

	m.om, err = newOSMon(bus, logf, m)
	if err != nil {
		return nil, err
	}
	if m.om == nil {
		return nil, errors.New("newOSMon returned nil, nil")
	}

	return m, nil
}

// NewStatic returns a Monitor that's a one-time snapshot of the network state
// but doesn't actually monitor for changes. It should only be used in tests
// and situations like cleanups or short-lived CLI programs.
func NewStatic() *Monitor {
	m := &Monitor{static: true}
	if st, err := m.interfaceStateUncached(); err == nil {
		m.ifState = st
	}
	return m
}

// InterfaceState returns the latest snapshot of the machine's network
// interfaces.
//
// The returned value is owned by Mon; it must not be modified.
func (m *Monitor) InterfaceState() *State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ifState
}

func (m *Monitor) interfaceStateUncached() (*State, error) {
	return getState(m.tsIfName)
}

// SetTailscaleInterfaceName sets the name of the Tailscale interface. For
// example, "tailscale0", "tun0", "utun3", etc.
//
// This must be called only early in tailscaled startup before the monitor is
// used.
func (m *Monitor) SetTailscaleInterfaceName(ifName string) {
	m.tsIfName = ifName
}

// GatewayAndSelfIP returns the current network's default gateway, and
// the machine's default IP for that gateway.
//
// It's the same as interfaces.LikelyHomeRouterIP, but it caches the
// result until the monitor detects a network change.
func (m *Monitor) GatewayAndSelfIP() (gw, myIP netip.Addr, ok bool) {
	if !buildfeatures.HasPortMapper {
		return
	}
	if m.static {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gwValid {
		return m.gw, m.gwSelfIP, true
	}
	gw, myIP, ok = LikelyHomeRouterIP()
	changed := false
	if ok {
		changed = m.gw != gw || m.gwSelfIP != myIP
		m.gw, m.gwSelfIP = gw, myIP
		m.gwValid = true
	}
	if changed {
		m.logf("gateway and self IP changed: gw=%v self=%v", m.gw, m.gwSelfIP)
	}
	return gw, myIP, ok
}

// RegisterChangeCallback adds callback to the set of parties to be
// notified (in their own goroutine) when the network state changes.
// To remove this callback, call unregister (or close the monitor).
func (m *Monitor) RegisterChangeCallback(callback ChangeFunc) (unregister func()) {
	if m.static {
		return func() {}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	handle := m.cbs.Add(callback)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.cbs, handle)
	}
}

// Start starts the monitor.
// A monitor can only be started & closed once.
func (m *Monitor) Start() {
	if m.static {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closed {
		return
	}
	m.started = true

	if shouldMonitorTimeJump {
		m.wallTimer = time.AfterFunc(pollWallTimeInterval, m.pollWallTime)
	}

	if m.om == nil {
		return
	}
	m.goroutines.Add(2)
	go m.pump()
	go m.debounce()
}

// Close closes the monitor.
func (m *Monitor) Close() error {
	if m.static {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.stop)

	if m.wallTimer != nil {
		m.wallTimer.Stop()
	}

	var err error
	if m.om != nil {
		err = m.om.Close()
	}

	started := m.started
	m.mu.Unlock()

	if started {
		m.goroutines.Wait()
	}
	return err
}

// InjectEvent forces the monitor to pretend there was a network
// change and re-check the state of the network. Any registered
// ChangeFunc callbacks will be called within the event coalescing
// period (under a fraction of a second).
func (m *Monitor) InjectEvent() {
	if m.static {
		return
	}
	select {
	case m.change <- true:
	default:
		// Another change signal is already
		// buffered. Debounce will wake up soon
		// enough.
	}
}

// Poll forces the monitor to pretend there was a network
// change and re-check the state of the network.
//
// This is like InjectEvent but only fires ChangeFunc callbacks
// if the network state differed at all.
func (m *Monitor) Poll() {
	if m.static {
		return
	}
	select {
	case m.change <- false:
	default:
	}
}

func (m *Monitor) stopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

// pump continuously retrieves messages from the connection, notifying
// the change channel of changes, and stopping when a stop is issued.
func (m *Monitor) pump() {
	defer m.goroutines.Done()
	for !m.stopped() {
		msg, err := m.om.Receive()
		if err != nil {
			if m.stopped() {
				return
			}
			// Keep retrying while we're not closed.
			m.logf("error from link monitor: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if msg.ignore() {
			continue
		}
		m.Poll()
	}
}

// isInterestingInterface reports whether the provided interface should be
// considered when checking for network state changes.
// The ips parameter should be the IPs of the provided interface.
func (m *Monitor) isInterestingInterface(i Interface, ips []netip.Prefix) bool {
	if !m.om.IsInterestingInterface(i.Name) {
		return false
	}

	return true
}

// debounce calls the callback function with a delay between events
// and exits when a stop is issued.
func (m *Monitor) debounce() {
	defer m.goroutines.Done()
	for {
		var forceCallbacks bool
		select {
		case <-m.stop:
			return
		case forceCallbacks = <-m.change:
		}

		if newState, err := m.interfaceStateUncached(); err != nil {
			m.logf("interfaces.State: %v", err)
		} else {
			m.handlePotentialChange(newState, forceCallbacks)
		}

		select {
		case <-m.stop:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

var (
	metricChangeEq       = clientmetric.NewCounter("netmon_link_change_eq")
	metricChange         = clientmetric.NewCounter("netmon_link_change")
	metricChangeTimeJump = clientmetric.NewCounter("netmon_link_change_timejump")
	metricChangeMajor    = clientmetric.NewCounter("netmon_link_change_major")
)

// handlePotentialChange considers whether newState is different enough to wake
// up callers and updates the monitor's state if so.
//
// If forceCallbacks is true, they're always notified.
func (m *Monitor) handlePotentialChange(newState *State, forceCallbacks bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldState := m.ifState
	timeJumped := shouldMonitorTimeJump && m.checkWallTimeAdvanceLocked()
	if !timeJumped && !forceCallbacks && oldState.Equal(newState) {
		// Exactly equal. Nothing to do.
		metricChangeEq.Add(1)
		return
	}

	delta := ChangeDelta{
		Old:        oldState,
		New:        newState,
		TimeJumped: timeJumped,
	}

	delta.Major = m.IsMajorChangeFrom(oldState, newState)
	if delta.Major {
		m.gwValid = false

		if s1, s2 := oldState.String(), delta.New.String(); s1 == s2 {
			m.logf("[unexpected] network state changed, but stringification didn't: %v", s1)
			m.logf("[unexpected] old: %s", jsonSummary(oldState))
			m.logf("[unexpected] new: %s", jsonSummary(newState))
		}
	}
	m.ifState = newState
	// See if we have a queued or new time jump signal.
	if timeJumped {
		m.resetTimeJumpedLocked()
		if !delta.Major {
			// Only log if it wasn't an interesting change.
			m.logf("time jumped (probably wake from sleep); synthesizing major change event")
			delta.Major = true
		}
	}
	metricChange.Add(1)
	if delta.Major {
		metricChangeMajor.Add(1)
	}
	if delta.TimeJumped {
		metricChangeTimeJump.Add(1)
	}
	m.changed.Publish(delta)
	for _, cb := range m.cbs {
		go cb(&delta)
	}
}

// IsMajorChangeFrom reports whether the transition from s1 to s2 is
// a "major" change, where major roughly means it's worth tearing down
// a bunch of connections and rebinding.
//
// TODO(bradiftz): tigten this definition.
func (m *Monitor) IsMajorChangeFrom(s1, s2 *State) bool {
	if s1 == nil && s2 == nil {
		return false
	}
	if s1 == nil || s2 == nil {
		return true
	}
	if s1.HaveV6 != s2.HaveV6 ||
		s1.HaveV4 != s2.HaveV4 ||
		s1.IsExpensive != s2.IsExpensive ||
		s1.DefaultRouteInterface != s2.DefaultRouteInterface ||
		s1.HTTPProxy != s2.HTTPProxy ||
		s1.PAC != s2.PAC {
		return true
	}
	for iname, i := range s1.Interface {
		if iname == m.tsIfName {
			// Ignore changes in the Tailscale interface itself.
			continue
		}
		ips := s1.InterfaceIPs[iname]
		if !m.isInterestingInterface(i, ips) {
			continue
		}
		i2, ok := s2.Interface[iname]
		if !ok {
			return true
		}
		ips2, ok := s2.InterfaceIPs[iname]
		if !ok {
			return true
		}
		if !i.Equal(i2) || !prefixesMajorEqual(ips, ips2) {
			return true
		}
	}
	// Iterate over s2 in case there is a field in s2 that doesn't exist in s1
	for iname, i := range s2.Interface {
		if iname == m.tsIfName {
			// Ignore changes in the Tailscale interface itself.
			continue
		}
		ips := s2.InterfaceIPs[iname]
		if !m.isInterestingInterface(i, ips) {
			continue
		}
		i1, ok := s1.Interface[iname]
		if !ok {
			return true
		}
		ips1, ok := s1.InterfaceIPs[iname]
		if !ok {
			return true
		}
		if !i.Equal(i1) || !prefixesMajorEqual(ips, ips1) {
			return true
		}
	}
	return false
}

// prefixesMajorEqual reports whether a and b are equal after ignoring
// boring things like link-local, loopback, and multicast addresses.
func prefixesMajorEqual(a, b []netip.Prefix) bool {
	// trim returns a subslice of p with link local unicast,
	// loopback, and multicast prefixes removed from the front.
	trim := func(p []netip.Prefix) []netip.Prefix {
		for len(p) > 0 {
			a := p[0].Addr()
			if a.IsLinkLocalUnicast() || a.IsLoopback() || a.IsMulticast() {
				p = p[1:]
				continue
			}
			break
		}
		return p
	}
	for {
		a = trim(a)
		b = trim(b)
		if len(a) == 0 || len(b) == 0 {
			return len(a) == 0 && len(b) == 0
		}
		if a[0] != b[0] {
			return false
		}
		a, b = a[1:], b[1:]
	}
}

func jsonSummary(x any) any {
	j, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return j
}

func wallTime() time.Time {
	// From time package's docs: "The canonical way to strip a
	// monotonic clock reading is to use t = t.Round(0)."
	return time.Now().Round(0)
}

func (m *Monitor) pollWallTime() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if m.checkWallTimeAdvanceLocked() {
		m.InjectEvent()
	}
	m.wallTimer.Reset(pollWallTimeInterval)
}

// shouldMonitorTimeJump is whether we keep a regular periodic timer running in
// the background watching for jumps in wall time.
//
// We don't do this on mobile platforms for battery reasons, and because these
// platforms don't really sleep in the same way.
const shouldMonitorTimeJump = runtime.GOOS != "android" && runtime.GOOS != "ios" && runtime.GOOS != "plan9"

// checkWallTimeAdvanceLocked reports whether wall time jumped more than 150% of
// pollWallTimeInterval, indicating we probably just came out of sleep. Once a
// time jump is detected it must be reset by calling resetTimeJumpedLocked.
func (m *Monitor) checkWallTimeAdvanceLocked() bool {
	if !shouldMonitorTimeJump {
		panic("unreachable") // if callers are correct
	}
	now := wallTime()
	if now.Sub(m.lastWall) > pollWallTimeInterval*3/2 {
		m.timeJumped = true // it is reset by debounce.
	}
	m.lastWall = now
	return m.timeJumped
}

// resetTimeJumpedLocked consumes the signal set by checkWallTimeAdvanceLocked.
func (m *Monitor) resetTimeJumpedLocked() {
	m.timeJumped = false
}
