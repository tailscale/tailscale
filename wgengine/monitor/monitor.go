// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux freebsd

// Package monitor provides facilities for monitoring network
// interface changes.
package monitor

import (
	"time"

	"tailscale.com/types/logger"
)

// Message represents a message returned from a connection.
// TODO(]|[): currently messages are being discarded, so the
// properties of the message haven't been defined.
type Message interface{}

// Conn represents the connection that is being monitored.
type Conn interface {
	Close() error
	Receive() (Message, error)
}

// ChangeFunc is a callback function that's called when
// an interface status changes.
type ChangeFunc func()

// Mon represents a monitoring instance.
type Mon struct {
	logf   logger.Logf
	cb     ChangeFunc
	conn   Conn
	change chan struct{}
	stop   chan struct{}
}

// New instantiates and starts a monitoring instance. Change notifications
// are propagated to the callback function.
func New(logf logger.Logf, callback ChangeFunc) (*Mon, error) {
	conn, err := NewConn()
	if err != nil {
		return nil, err
	}
	ret := &Mon{
		logf:   logf,
		cb:     callback,
		conn:   conn,
		change: make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	go ret.pump()
	go ret.debounce()
	return ret, nil
}

// Close is used to close the underlying connection.
func (m *Mon) Close() error {
	close(m.stop)
	return m.conn.Close()
}

// pump continuously retrieves messages from the connection, notifying
// the change channel of changes, and stopping when a stop is issued.
func (m *Mon) pump() {
	for {
		_, err := m.conn.Receive()
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

		select {
		case m.change <- struct{}{}:
		default:
		}
	}
}

// debounce calls the callback function with a delay between events
// and exits when a stop is issued.
func (m *Mon) debounce() {
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
