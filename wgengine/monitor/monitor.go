// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package monitor provides facilities for monitoring network
// interface and route changes. It primarily exists to know when
// portable devices move between different networks.
package monitor

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

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

// ChangeFunc is a callback function that's called when the network
// changed. The changed parameter is whether the network changed
// enough for interfaces.State to have changed since the last
// callback.
type ChangeFunc func(changed bool, state *interfaces.State)

// An allocated callbackHandle's address is the Mon.cbs map key.
type callbackHandle byte

// Mon represents a monitoring instance.
type Mon struct {
	logf   logger.Logf
	om     osMon // nil means not supported on this platform
	change chan struct{}
	stop   chan struct{}

	mu       sync.Mutex // guards cbs
	cbs      map[*callbackHandle]ChangeFunc
	ifState  *interfaces.State
	gwValid  bool // whether gw and gwSelfIP are valid (cached)x
	gw       netaddr.IP
	gwSelfIP netaddr.IP

	onceStart  sync.Once
	started    bool
	goroutines sync.WaitGroup
}

// New instantiates and starts a monitoring instance.
// The returned monitor is inactive until it's started by the Start method.
// Use RegisterChangeCallback to get notified of network changes.
func New(logf logger.Logf) (*Mon, error) {
	logf = logger.WithPrefix(logf, "monitor: ")
	m := &Mon{
		logf:   logf,
		cbs:    map[*callbackHandle]ChangeFunc{},
		change: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	st, err := m.interfaceStateUncached()
	if err != nil {
		return nil, err
	}
	m.ifState = st

	m.om, err = newOSMon(logf, m)
	if err != nil {
		return nil, err
	}
	if m.om == nil {
		return nil, errors.New("newOSMon returned nil, nil")
	}

	return m, nil
}

// InterfaceState returns the state of the machine's network interfaces,
// without any Tailscale ones.
func (m *Mon) InterfaceState() *interfaces.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ifState
}

func (m *Mon) interfaceStateUncached() (*interfaces.State, error) {
	s, err := interfaces.GetState()
	if s != nil {
		s.RemoveTailscaleInterfaces()
		s.RemoveUninterestingInterfacesAndAddresses()
	}
	return s, err
}

// GatewayAndSelfIP returns the current network's default gateway, and
// the machine's default IP for that gateway.
//
// It's the same as interfaces.LikelyHomeRouterIP, but it caches the
// result until the monitor detects a network change.
func (m *Mon) GatewayAndSelfIP() (gw, myIP netaddr.IP, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gwValid {
		return m.gw, m.gwSelfIP, true
	}
	gw, myIP, ok = interfaces.LikelyHomeRouterIP()
	if ok {
		m.gw, m.gwSelfIP, m.gwValid = gw, myIP, true
	}
	return gw, myIP, ok
}

// RegisterChangeCallback adds callback to the set of parties to be
// notified (in their own goroutine) when the network state changes.
// To remove this callback, call unregister (or close the monitor).
func (m *Mon) RegisterChangeCallback(callback ChangeFunc) (unregister func()) {
	handle := new(callbackHandle)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cbs[handle] = callback
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.cbs, handle)
	}
}

// Start starts the monitor.
// A monitor can only be started & closed once.
func (m *Mon) Start() {
	m.onceStart.Do(func() {
		if m.om == nil {
			return
		}
		m.started = true
		m.goroutines.Add(2)
		go m.pump()
		go m.debounce()
	})
}

// Close closes the monitor.
// It may only be called once.
func (m *Mon) Close() error {
	close(m.stop)
	var err error
	if m.om != nil {
		err = m.om.Close()
	}
	// If it was previously started, wait for those goroutines to finish.
	m.onceStart.Do(func() {})
	if m.started {
		m.goroutines.Wait()
	}
	return err
}

// InjectEvent forces the monitor to pretend there was a network
// change and re-check the state of the network. Any registered
// ChangeFunc callbacks will be called within the event coalescing
// period (under a fraction of a second).
func (m *Mon) InjectEvent() {
	select {
	case m.change <- struct{}{}:
	default:
		// Another change signal is already
		// buffered. Debounce will wake up soon
		// enough.
	}
}

func (m *Mon) stopped() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

// pump continuously retrieves messages from the connection, notifying
// the change channel of changes, and stopping when a stop is issued.
func (m *Mon) pump() {
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
		m.InjectEvent()
	}
}

// debounce calls the callback function with a delay between events
// and exits when a stop is issued.
func (m *Mon) debounce() {
	defer m.goroutines.Done()
	for {
		select {
		case <-m.stop:
			return
		case <-m.change:
		}

		if curState, err := m.interfaceStateUncached(); err != nil {
			m.logf("interfaces.State: %v", err)
		} else {
			m.mu.Lock()
			oldState := m.ifState
			changed := !curState.Equal(oldState)
			if changed {
				m.gwValid = false
				m.ifState = curState

				if s1, s2 := oldState.String(), curState.String(); s1 == s2 {
					m.logf("[unexpected] network state changed, but stringification didn't: %v\nold: %s\nnew: %s\n", s1,
						jsonSummary(oldState), jsonSummary(curState))
				}
			}
			for _, cb := range m.cbs {
				go cb(changed, m.ifState)
			}
			m.mu.Unlock()
		}

		select {
		case <-m.stop:
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func jsonSummary(x interface{}) interface{} {
	j, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return j
}
