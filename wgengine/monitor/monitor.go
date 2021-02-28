// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package monitor provides facilities for monitoring network
// interface and route changes. It primarily exists to know when
// portable devices move between different networks.
package monitor

import (
	"sync"
	"time"

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

// ChangeFunc is a callback function that's called when
// an interface status changes.
type ChangeFunc func()

// An allocated callbackHandle's address is the Mon.cbs map key.
type callbackHandle byte

// Mon represents a monitoring instance.
type Mon struct {
	logf   logger.Logf
	om     osMon // nil means not supported on this platform
	change chan struct{}
	stop   chan struct{}

	mu  sync.Mutex // guards cbs
	cbs map[*callbackHandle]ChangeFunc

	onceStart  sync.Once
	started    bool
	goroutines sync.WaitGroup
}

// New instantiates and starts a monitoring instance.
// The returned monitor is inactive until it's started by the Start method.
// Use RegisterChangeCallback to get notified of network changes.
func New(logf logger.Logf) (*Mon, error) {
	logf = logger.WithPrefix(logf, "monitor: ")
	om, err := newOSMon(logf)
	if err != nil {
		return nil, err
	}
	return &Mon{
		logf:   logf,
		cbs:    map[*callbackHandle]ChangeFunc{},
		om:     om,
		change: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}, nil
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

// pump continuously retrieves messages from the connection, notifying
// the change channel of changes, and stopping when a stop is issued.
func (m *Mon) pump() {
	defer m.goroutines.Done()
	for {
		msg, err := m.om.Receive()
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			// Keep retrying while we're not closed.
			m.logf("error from link monitor: %v", err)
			time.Sleep(time.Second)
			continue
		}
		if msg.ignore() {
			continue
		}
		select {
		case m.change <- struct{}{}:
		case <-m.stop:
			return
		}
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

		m.mu.Lock()
		for _, cb := range m.cbs {
			go cb()
		}
		m.mu.Unlock()

		select {
		case <-m.stop:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
