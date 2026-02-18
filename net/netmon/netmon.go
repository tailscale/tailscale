// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package monitor provides facilities for monitoring network
// interface and route changes. It primarily exists to know when
// portable devices move between different networks.
package netmon

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"slices"
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
}

// IsInterestingInterface is the function used to determine whether
// a given interface name is interesting enough to pay attention to
// for network change monitoring purposes.
//
// If nil, all interfaces are considered interesting.
var IsInterestingInterface func(Interface, []netip.Prefix) bool

// Monitor represents a monitoring instance.
type Monitor struct {
	logf    logger.Logf
	b       *eventbus.Client
	changed *eventbus.Publisher[ChangeDelta]

	om     osMon         // nil means not supported on this platform
	change chan bool     // send false to wake poller, true to also force ChangeDeltas be sent
	stop   chan struct{} // closed on Stop
	static bool          // static Monitor that doesn't actually monitor

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
//
// Use NewChangeDelta to construct a delta and compute the cached fields.
type ChangeDelta struct {
	// old is the old interface state, if known.
	// It's nil if the old state is unknown.
	old *State

	// New is the new network state.
	// It is always non-nil.
	new *State

	// TimeJumped is whether there was a big jump in wall time since the last
	// time we checked. This is a hint that a sleeping device might have
	// come out of sleep.
	TimeJumped bool

	DefaultRouteInterface string

	// Computed Fields

	DefaultInterfaceChanged     bool // whether default route interface changed
	IsLessExpensive             bool // whether new state's default interface is less expensive than old.
	HasPACOrProxyConfigChanged  bool // whether PAC/HTTP proxy config changed
	InterfaceIPsChanged         bool // whether any interface IPs changed in a meaningful way
	AvailableProtocolsChanged   bool // whether we have seen a change in available IPv4/IPv6
	DefaultInterfaceMaybeViable bool // whether the default interface is potentially viable (has usable IPs, is up and is not the tunnel itself)
	IsInitialState              bool // whether this is the initial state (old == nil, new != nil)

	// RebindLikelyRequired combines the various fields above to report whether this change likely requires us
	// to rebind sockets.  This is a very conservative estimate and covers a number ofcases where a rebind
	// may not be strictly necessary.  Consumers of the ChangeDelta should consider checking the individual fields
	// above or the state of their sockets.
	RebindLikelyRequired bool
}

// CurrentState returns the current (new) state after the change.
func (cd *ChangeDelta) CurrentState() *State {
	return cd.new
}

// NewChangeDelta builds a ChangeDelta and eagerly computes the cached fields.
// forceViability, if true, forces DefaultInterfaceMaybeViable to be true regardless of the
// actual state of the default interface.  This is useful in testing.
func NewChangeDelta(old, new *State, timeJumped bool, forceViability bool) (*ChangeDelta, error) {
	cd := ChangeDelta{
		old:        old,
		new:        new,
		TimeJumped: timeJumped,
	}

	if cd.new == nil {
		log.Printf("[unexpected] NewChangeDelta called with nil new state")
		return nil, errors.New("new state cannot be nil")
	} else if cd.old == nil && cd.new != nil {
		cd.DefaultInterfaceChanged = cd.new.DefaultRouteInterface != ""
		cd.IsLessExpensive = false
		cd.HasPACOrProxyConfigChanged = true
		cd.InterfaceIPsChanged = true
		cd.IsInitialState = true
	} else {
		cd.AvailableProtocolsChanged = (cd.old.HaveV4 != cd.new.HaveV4) || (cd.old.HaveV6 != cd.new.HaveV6)
		cd.DefaultInterfaceChanged = cd.old.DefaultRouteInterface != cd.new.DefaultRouteInterface
		cd.IsLessExpensive = cd.old.IsExpensive && !cd.new.IsExpensive
		cd.HasPACOrProxyConfigChanged = (cd.old.PAC != cd.new.PAC) || (cd.old.HTTPProxy != cd.new.HTTPProxy)
		cd.InterfaceIPsChanged = cd.isInterestingInterfaceChange()
	}

	cd.DefaultRouteInterface = new.DefaultRouteInterface
	defIf := new.Interface[cd.DefaultRouteInterface]

	tsIfName, err := TailscaleInterfaceName()

	// The default interface is not viable if it is down or it is the Tailscale interface itself.
	if !forceViability && (!defIf.IsUp() || (err == nil && cd.DefaultRouteInterface == tsIfName)) {
		cd.DefaultInterfaceMaybeViable = false
	} else {
		cd.DefaultInterfaceMaybeViable = true
	}

	// Compute rebind requirement.   The default interface needs to be viable and
	// one of the other conditions needs to be true.
	cd.RebindLikelyRequired = (cd.old == nil ||
		cd.TimeJumped ||
		cd.DefaultInterfaceChanged ||
		cd.InterfaceIPsChanged ||
		cd.IsLessExpensive ||
		cd.HasPACOrProxyConfigChanged ||
		cd.AvailableProtocolsChanged) &&
		cd.DefaultInterfaceMaybeViable

	return &cd, nil
}

// StateDesc returns a description of the old and new states for logging.
func (cd *ChangeDelta) StateDesc() string {
	return fmt.Sprintf("old: %v new: %v", cd.old, cd.new)
}

// InterfaceIPDisappeared reports whether the given IP address exists on any interface
// in the old state, but not in the new state.
func (cd *ChangeDelta) InterfaceIPDisappeared(ip netip.Addr) bool {
	if cd.old == nil {
		return false
	}
	if cd.new == nil && cd.old.HasIP(ip) {
		return true
	}
	return cd.new.HasIP(ip) && !cd.old.HasIP(ip)
}

// AnyInterfaceUp reports whether any interfaces are up in the new state.
func (cd *ChangeDelta) AnyInterfaceUp() bool {
	if cd.new == nil {
		return false
	}
	return cd.new.AnyInterfaceUp()
}

// isInterestingInterfaceChange reports whether any interfaces have changed in a meaningful way.
// This excludes interfaces that are not interesting per IsInterestingInterface and
// filters out changes to interface IPs that that are uninteresting (e.g. link-local addresses).
func (cd *ChangeDelta) isInterestingInterfaceChange() bool {
	// If there is no old state, everything is considered changed.
	if cd.old == nil {
		return true
	}

	// Compare interfaces in both directions.  Old to new and new to old.
	tsIfName, ifNameErr := TailscaleInterfaceName()

	for iname, oldInterface := range cd.old.Interface {
		if ifNameErr == nil && iname == tsIfName {
			// Ignore changes in the Tailscale interface itself
			continue
		}
		oldIps := filterRoutableIPs(cd.old.InterfaceIPs[iname])
		if IsInterestingInterface != nil && !IsInterestingInterface(oldInterface, oldIps) {
			continue
		}

		// Old interfaces with no routable addresses are not interesting
		if len(oldIps) == 0 {
			continue
		}

		// The old interface doesn't exist in the new interface set and it has
		// a global unicast IP.  That's considered a change from the perspective
		// of anything that may have been bound to it. If it didn't have a global
		// unicast IP, it's not interesting.
		newInterface, ok := cd.new.Interface[iname]
		if !ok {
			return true
		}
		newIps, ok := cd.new.InterfaceIPs[iname]
		if !ok {
			return true
		}
		newIps = filterRoutableIPs(newIps)

		if !oldInterface.Equal(newInterface) || !prefixesEqual(oldIps, newIps) {
			return true
		}
	}

	for iname, newInterface := range cd.new.Interface {
		if ifNameErr == nil && iname == tsIfName {
			// Ignore changes in the Tailscale interface itself
			continue
		}
		newIps := filterRoutableIPs(cd.new.InterfaceIPs[iname])
		if IsInterestingInterface != nil && !IsInterestingInterface(newInterface, newIps) {
			continue
		}

		// New interfaces with no routable addresses are not interesting
		if len(newIps) == 0 {
			continue
		}

		oldInterface, ok := cd.old.Interface[iname]
		if !ok {
			return true
		}

		oldIps, ok := cd.old.InterfaceIPs[iname]
		if !ok {
			// Redundant but we can't dig up the "old" IPs for this interface.
			return true
		}
		oldIps = filterRoutableIPs(oldIps)

		// The interface's IPs, Name, MTU, etc have changed.  This is definitely interesting.
		if !newInterface.Equal(oldInterface) || !prefixesEqual(oldIps, newIps) {
			return true
		}
	}
	return false
}

func filterRoutableIPs(addrs []netip.Prefix) []netip.Prefix {
	var filtered []netip.Prefix
	for _, pfx := range addrs {
		a := pfx.Addr()
		// Skip link-local multicast addresses.
		if a.IsLinkLocalMulticast() {
			continue
		}

		if isUsableV4(a) || isUsableV6(a) {
			filtered = append(filtered, pfx)
		}
	}
	return filtered
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
	return getState(tsIfProps.tsIfName())
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
		// 1s is reasonable debounce time for network changes.  Events such as undocking a laptop
		// or roaming onto wifi will often generate multiple events in quick succession as interfaces
		// flap.  We want to avoid spamming consumers of these events.
		case <-time.After(1000 * time.Millisecond):
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

	delta, err := NewChangeDelta(oldState, newState, timeJumped, false)
	if err != nil {
		m.logf("[unexpected] error creating ChangeDelta: %v", err)
		return
	}

	if delta.RebindLikelyRequired {
		m.gwValid = false
	}
	m.ifState = newState
	// See if we have a queued or new time jump signal.
	if timeJumped {
		m.resetTimeJumpedLocked()
	}
	metricChange.Add(1)
	if delta.RebindLikelyRequired {
		metricChangeMajor.Add(1)
	}
	if delta.TimeJumped {
		metricChangeTimeJump.Add(1)
	}
	m.changed.Publish(*delta)
	for _, cb := range m.cbs {
		go cb(delta)
	}
}

// reports whether a and b contain the same set of prefixes regardless of order.
func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}

	aa := make([]netip.Prefix, len(a))
	bb := make([]netip.Prefix, len(b))
	copy(aa, a)
	copy(bb, b)

	less := func(x, y netip.Prefix) int {
		return x.Addr().Compare(y.Addr())
	}

	slices.SortFunc(aa, less)
	slices.SortFunc(bb, less)
	return slices.Equal(aa, bb)
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
