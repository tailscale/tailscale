// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package monitor provides facilities for monitoring network
// interface changes.
package monitor

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

// message represents a message returned from an osMon.
//
// TODO: currently messages are being discarded, so the properties of
// the message haven't been defined.
type message interface{}

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

// Mon represents a monitoring instance.
type Mon struct {
	logf   logger.Logf
	cb     ChangeFunc
	om     osMon // nil means not supported on this platform
	change chan struct{}
	stop   chan struct{}

	onceStart  sync.Once
	started    bool
	goroutines sync.WaitGroup
}

// New instantiates and starts a monitoring instance. Change notifications
// are propagated to the callback function.
// The returned monitor is inactive until it's started by the Start method.
func New(logf logger.Logf, callback ChangeFunc) (*Mon, error) {
	om, err := newOSMon()
	if err != nil {
		return nil, err
	}
	return &Mon{
		logf:   logf,
		cb:     callback,
		om:     om,
		change: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}, nil
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
	last := interfaceSummary()
	for {
		_, err := m.om.Receive()
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			// Keep retrying while we're not closed.
			m.logf("Error receiving from connection: %v", err)
			time.Sleep(time.Second)
			continue
		}

		cur := interfaceSummary()
		if cur == last {
			continue
		}
		m.logf("wgengine/monitor: now %v (was %v)", cur, last)
		last = cur

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

		m.cb()

		select {
		case <-m.stop:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func interfaceSummary() string {
	var sb strings.Builder
	_ = interfaces.ForeachInterfaceAddress(func(ni interfaces.Interface, addr net.IP) {
		if runtime.GOOS == "linux" && strings.HasPrefix(ni.Name, "tailscale") {
			// Skip tailscale0, etc on Linux.
			return
		}
		if ni.IsUp() {
			fmt.Fprintf(&sb, "%s=%s ", ni.Name, addr)
		}
	})
	return strings.TrimSpace(sb.String())
}
