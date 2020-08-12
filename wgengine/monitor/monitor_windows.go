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
	"tailscale.com/types/logger"
)

var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	notifyAddrChangeProc  = iphlpapi.NewProc("NotifyAddrChange")
	notifyRouteChangeProc = iphlpapi.NewProc("NotifyRouteChange")
)

type unspecifiedMessage struct{}

func (unspecifiedMessage) ignore() bool { return false }

type winMon struct {
	ctx    context.Context
	cancel context.CancelFunc

	logf logger.Logf

	mu    sync.Mutex
	event windows.Handle
}

func newOSMon(logf logger.Logf) (osMon, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &winMon{
		logf:   logf,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (m *winMon) Close() error {
	m.cancel()

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
	evt, err := windows.WaitForSingleObject(o.HEvent, windows.INFINITE)
	if m.ctx.Err() != nil {
		return nil, errClosed
	}
	if err != nil {
		m.logf("notifyRouteChange: %v", err)
		return nil, err
	}
	d := time.Since(t0)
	m.logf("got windows change event after %v: %+v", d, evt)

	m.mu.Lock()
	m.event = 0
	m.mu.Unlock()

	return unspecifiedMessage{}, nil
}

func notifyAddrChange(h *windows.Handle, o *windows.Overlapped) error {
	return callNotifyProc(notifyAddrChangeProc, h, o)
}

func notifyRouteChange(h *windows.Handle, o *windows.Overlapped) error {
	return callNotifyProc(notifyAddrChangeProc, h, o)
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
