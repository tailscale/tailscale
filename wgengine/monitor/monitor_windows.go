// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
	iphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	notifyAddrChangeProc     = iphlpapi.NewProc("NotifyAddrChange")
	notifyRouteChangeProc    = iphlpapi.NewProc("NotifyRouteChange")
	cancelIPChangeNotifyProc = iphlpapi.NewProc("CancelIPChangeNotify")
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
	ctx         context.Context
	cancel      context.CancelFunc
	messagec    chan messageOrError
	logf        logger.Logf
	pollTicker  *time.Ticker
	lastState   *interfaces.State
	closeHandle windows.Handle // signaled upon close

	mu            sync.Mutex
	lastNetChange time.Time
	inFastPoll    bool // recent net change event made us go into fast polling mode (to detect proxy changes)
}

func newOSMon(logf logger.Logf) (osMon, error) {
	closeHandle, err := windows.CreateEvent(nil, 1 /* manual reset */, 0 /* unsignaled */, nil /* no name */)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &winMon{
		logf:        logf,
		ctx:         ctx,
		cancel:      cancel,
		messagec:    make(chan messageOrError, 1),
		pollTicker:  time.NewTicker(pollIntervalSlow),
		closeHandle: closeHandle,
	}
	go m.awaitIPAndRouteChanges()
	return m, nil
}

func (m *winMon) Close() error {
	m.cancel()
	m.pollTicker.Stop()
	windows.SetEvent(m.closeHandle) // wakes up any reader blocked in Receive
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

	oaddr := new(windows.Overlapped)
	oroute := new(windows.Overlapped)

	err := notifyAddrChange(&oaddr.HEvent, oaddr)
	if err != nil {
		m.logf("notifyAddrChange: %v", err)
		return nil, err
	}
	defer cancelIPChangeNotifyProc.Call(uintptr(unsafe.Pointer(oaddr)))

	err = notifyRouteChange(&oroute.HEvent, oroute)
	if err != nil {
		m.logf("notifyRouteChange: %v", err)
		return nil, err
	}
	defer cancelIPChangeNotifyProc.Call(uintptr(unsafe.Pointer(oroute)))

	t0 := time.Now()
	eventNum, err := windows.WaitForMultipleObjects([]windows.Handle{
		m.closeHandle, // eventNum 0
		oaddr.HEvent,  // eventNum 1
		oroute.HEvent, // eventNum 2
	}, false, windows.INFINITE)
	if m.ctx.Err() != nil || (err == nil && eventNum == 0) {
		return nil, errClosed
	}
	if err != nil {
		m.logf("waitForSingleObject: %v", err)
		return nil, err
	}

	d := time.Since(t0)
	var eventStr string
	switch eventNum {
	case 1:
		eventStr = "addr"
	case 2:
		eventStr = "route"
	default:
		eventStr = fmt.Sprintf("%d [unexpected]", eventNum)
	}
	m.logf("got windows change event after %v: evt=%s", d, eventStr)

	m.mu.Lock()
	{
		m.lastNetChange = time.Now()

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

// forceOverlapEscape exists purely so we can assign to it
// and make sure that callNotifyProc's 'o' argument does not
// stay stack allocated.
var forceOverlapEscape atomic.Value // of *windows.Overlapped

func callNotifyProc(p *syscall.LazyProc, h *windows.Handle, o *windows.Overlapped) error {
	forceOverlapEscape.Store(o)
	r1, _, e1 := syscall.Syscall(p.Addr(), 2, uintptr(unsafe.Pointer(h)), uintptr(unsafe.Pointer(o)), 0)
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
