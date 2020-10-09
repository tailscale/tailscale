// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

const (
	pollIntervalSlow = 15 * time.Second
	pollIntervalFast = 3 * time.Second
	pollFastFor      = 30 * time.Second
)

var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	notifyAddrChangeProc  = iphlpapi.NewProc("NotifyAddrChange")
	notifyRouteChangeProc = iphlpapi.NewProc("NotifyRouteChange")
)

type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

type pollStateChangedMessage struct{}

func (pollStateChangedMessage) ignore() bool { return false }

type messageOrError struct {
	message
	error
}

type winMon struct {
	ctx        context.Context
	cancel     context.CancelFunc
	messagec   chan messageOrError
	logf       logger.Logf
	pollTicker *time.Ticker
	lastState  *interfaces.State

	mu            sync.Mutex
	event         windows.Handle
	lastNetChange time.Time
	inFastPoll    bool // recent net change event made us go into fast polling mode (to detect proxy changes)
}

func newOSMon(logf logger.Logf) (osMon, error) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &winMon{
		logf:       logf,
		ctx:        ctx,
		cancel:     cancel,
		messagec:   make(chan messageOrError, 1),
		pollTicker: time.NewTicker(pollIntervalSlow),
	}
	go m.awaitIPAndRouteChanges()
	return m, nil
}

func (m *winMon) Close() error {
	m.cancel()
	m.pollTicker.Stop()

	m.mu.Lock()
	defer m.mu.Unlock()
	if h := m.event; h != 0 {
		// Wake up any reader blocked in Receive.
		windows.SetEvent(h)
	}

	return nil
}

var errClosed = errors.New("closed")

func (m *winMon) Receive() (message, error) {
	for {
		select {
		case <-m.ctx.Done():
			return nil, errClosed
		case me := <-m.messagec:
			return me.message, me.error
		case <-m.pollTicker.C:
			if m.stateChanged() {
				m.logf("interface state changed (on poll)")
				return pollStateChangedMessage{}, nil
			}
			m.mu.Lock()
			if m.inFastPoll && time.Since(m.lastNetChange) > pollFastFor {
				m.inFastPoll = false
				m.pollTicker.Reset(pollIntervalSlow)
			}
			m.mu.Unlock()
		}
	}
}

func (m *winMon) stateChanged() bool {
	st, err := interfaces.GetState()
	if err != nil {
		return false
	}
	changed := !st.Equal(m.lastState)
	m.lastState = st
	return changed
}

func (m *winMon) awaitIPAndRouteChanges() {
	for {
		msg, err := m.getIPOrRouteChangeMessage()
		if err == errClosed {
			return
		}
		select {
		case m.messagec <- messageOrError{msg, err}:
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *winMon) getIPOrRouteChangeMessage() (message, error) {
	if m.ctx.Err() != nil {
		return nil, errClosed
	}

	var o windows.Overlapped
	h, err := windows.CreateEvent(nil, 1 /* true*/, 0 /* unsignaled */, nil /* no name */)
	if err != nil {
		m.logf("CreateEvent: %v", err)
		return nil, err
	}
	defer windows.CloseHandle(h)

	m.mu.Lock()
	m.event = h
	m.mu.Unlock()

	o.HEvent = h

	err = notifyAddrChange(&h, &o)
	if err != nil {
		m.logf("notifyAddrChange: %v", err)
		return nil, err
	}
	err = notifyRouteChange(&h, &o)
	if err != nil {
		m.logf("notifyRouteChange: %v", err)
		return nil, err
	}

	t0 := time.Now()
	_, err = windows.WaitForSingleObject(o.HEvent, windows.INFINITE)
	if m.ctx.Err() != nil {
		return nil, errClosed
	}
	if err != nil {
		m.logf("waitForSingleObject: %v", err)
		return nil, err
	}
	d := time.Since(t0)
	m.logf("got windows change event after %v", d)

	m.mu.Lock()
	{
		m.lastNetChange = time.Now()
		m.event = 0

		// Something changed, so assume Windows is about to
		// discover its new proxy settings from WPAD, which
		// seems to take a bit. Poll heavily for awhile.
		m.logf("starting quick poll, waiting for WPAD change")
		m.inFastPoll = true
		m.pollTicker.Reset(pollIntervalFast)
	}
	m.mu.Unlock()

	return unspecifiedMessage{}, nil
}

func notifyAddrChange(h *windows.Handle, o *windows.Overlapped) error {
	return callNotifyProc(notifyAddrChangeProc, h, o)
}

func notifyRouteChange(h *windows.Handle, o *windows.Overlapped) error {
	return callNotifyProc(notifyRouteChangeProc, h, o)
}

func callNotifyProc(p *syscall.LazyProc, h *windows.Handle, o *windows.Overlapped) error {
	r1, _, e1 := p.Call(uintptr(unsafe.Pointer(h)), uintptr(unsafe.Pointer(o)))
	expect := uintptr(0)
	if h != nil || o != nil {
		const ERROR_IO_PENDING = 997
		expect = ERROR_IO_PENDING
	}
	if r1 == expect {
		return nil
	}
	return e1
}
