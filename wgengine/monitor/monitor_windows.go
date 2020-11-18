// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"context"
	"errors"
	"fmt"
	"runtime"
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
	iphlpapi                 = syscall.NewLazyDLL("iphlpapi.dll")
	notifyAddrChangeProc     = iphlpapi.NewProc("NotifyAddrChange")
	notifyRouteChangeProc    = iphlpapi.NewProc("NotifyRouteChange")
	cancelIPChangeNotifyProc = iphlpapi.NewProc("CancelIPChangeNotify")
)

const (
	_STATUS_PENDING = 0x00000103 // 259
	_STATUS_WAIT_0  = 0
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

	// TODO(bradfitz): locking ourselves to an OS thread here
	// likely isn't necessary, but also can't really hurt.
	// We'll be blocked in windows.WaitForMultipleObjects below
	// anyway, so might as well stay on this thread during the
	// notify calls and cancel funcs.
	// Given the past memory corruption from misuse of these APIs,
	// and my continued lack of understanding of Windows APIs,
	// I'll be paranoid. But perhaps we can remove this once
	// we understand more.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	addrHandle, oaddr, cancel, err := notifyAddrChange()
	if err != nil {
		m.logf("notifyAddrChange: %v", err)
		return nil, err
	}
	defer cancel()

	routeHandle, oroute, cancel, err := notifyRouteChange()
	if err != nil {
		m.logf("notifyRouteChange: %v", err)
		return nil, err
	}
	defer cancel()

	t0 := time.Now()
	eventNum, err := windows.WaitForMultipleObjects([]windows.Handle{
		m.closeHandle, // eventNum 0
		addrHandle,    // eventNum 1
		routeHandle,   // eventNum 2
	}, false, windows.INFINITE)
	if m.ctx.Err() != nil || (err == nil && eventNum == 0) {
		return nil, errClosed
	}
	if err != nil {
		m.logf("waitForMultipleObjects: %v", err)
		return nil, err
	}

	d := time.Since(t0)
	var eventStr string

	// notifyAddrChange and notifyRouteChange both seem to return the same
	// handle value. Determine which fired by looking at the "Internal" (sic)
	// field of the Ovelapped instead.
	// TODO(bradfitz): maybe clean this up; see TODO in callNotifyProc.
	if (eventNum == 1 || eventNum == 2) && addrHandle == routeHandle {
		if oaddr.Internal == _STATUS_WAIT_0 && oroute.Internal == _STATUS_PENDING {
			eventStr = "addr-o" // "-o" overlapped suffix to distinguish from "addr" below
		} else if oroute.Internal == _STATUS_WAIT_0 && oaddr.Internal == _STATUS_PENDING {
			eventStr = "route-o"
		} else {
			eventStr = fmt.Sprintf("[unexpected] addr.internal=%d; route.internal=%d", oaddr.Internal, oroute.Internal)
		}
	} else {
		switch eventNum {
		case 1:
			eventStr = "addr"
		case 2:
			eventStr = "route"
		default:
			eventStr = fmt.Sprintf("%d [unexpected]", eventNum)
		}
	}
	m.logf("got windows change event after %v: evt=%s", d, eventStr)

	m.mu.Lock()
	{
		m.lastNetChange = time.Now()

		// Something changed, so assume Windows is about to
		// discover its new proxy settings from WPAD, which
		// seems to take a bit. Poll heavily for awhile.
		m.inFastPoll = true
		m.pollTicker.Reset(pollIntervalFast)
	}
	m.mu.Unlock()

	return unspecifiedMessage{}, nil
}

func notifyAddrChange() (h windows.Handle, o *windows.Overlapped, cancel func(), err error) {
	return callNotifyProc(notifyAddrChangeProc)
}

func notifyRouteChange() (h windows.Handle, o *windows.Overlapped, cancel func(), err error) {
	return callNotifyProc(notifyRouteChangeProc)
}

func callNotifyProc(p *syscall.LazyProc) (h windows.Handle, o *windows.Overlapped, cancel func(), err error) {
	o = new(windows.Overlapped)

	// TODO(bradfitz): understand why this if-false code doesn't
	// work, even though the docs online suggest we should pass an
	// event in the overlapped.Hevent field.
	// The docs at
	// https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped
	// says that o.HEvent can be zero, though, which seems to work.
	// Note that the returned windows.Handle returns the same value for both
	// notifyAddrChange and notifyRouteChange, which is why our caller needs
	// to look at the returned Overlapped's Internal field to see which case
	// fired. That's also worth understanding more.
	// See crawshaw's comment at https://github.com/tailscale/tailscale/pull/944#discussion_r526469186
	// too.
	if false {
		evt, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return 0, nil, nil, err
		}
		o.HEvent = evt
	}

	r1, _, e1 := syscall.Syscall(p.Addr(), 2, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(o)), 0)

	// We expect ERROR_IO_PENDING.
	if syscall.Errno(r1) != windows.ERROR_IO_PENDING {
		return 0, nil, nil, e1
	}

	cancel = func() {
		cancelIPChangeNotifyProc.Call(uintptr(unsafe.Pointer(o)))
	}
	return h, o, cancel, nil
}
