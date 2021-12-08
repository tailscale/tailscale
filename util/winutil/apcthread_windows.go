// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

var (
	k32                       = windows.NewLazySystemDLL("kernel32.dll")
	procWaitForSingleObjectEx = k32.NewProc("WaitForSingleObjectEx")
)

func waitForSingleObjectEx(handle windows.Handle, timeout uint32, alertable bool) (uint32, error) {
	var ua uintptr
	if alertable {
		ua = 1
	}
	code, _, err := procWaitForSingleObjectEx.Call(uintptr(handle), uintptr(timeout), ua)
	code32 := uint32(code)
	if code32 == windows.WAIT_FAILED {
		return code32, err
	}
	return code32, nil
}

const (
	noPendingIdleTimeout = 30000
	reqChanBufSize       = 64
)

type APCChannel chan []reflect.Value

func MakeAPCChannel() APCChannel {
	return make(APCChannel)
}

type APCRequest interface {
	Begin() *APCChannel
}

type APCChannelResolver interface {
	GetChannel([]reflect.Value) *APCChannel
}

type APCCallbackInfo struct {
	Function reflect.Type
	Resolver APCChannelResolver
}

type apcThread struct {
	once    sync.Once
	event   windows.Handle
	reqChan chan APCRequest
	pending map[*APCChannel]struct{}
	mu      sync.RWMutex // protects cbinfo
	cbinfo  map[APCCallbackInfo]uintptr
}

func (t *apcThread) init() {
	var err error
	// Auto-reset event for signaling that new requests are present
	t.event, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		panic(fmt.Sprintf("Creating apcThread event: %v", err))
	}
	t.reqChan = make(chan APCRequest, reqChanBufSize)
	t.pending = make(map[*APCChannel]struct{})
	t.cbinfo = make(map[APCCallbackInfo]uintptr)
}

func (t *apcThread) submitWork(req APCRequest) error {
	// Lazily start the goroutine
	t.once.Do(func() {
		go t.run()
	})
	t.reqChan <- req
	// We need to set an event to poke the APC thread into checking t.reqChan.
	return windows.SetEvent(t.event)
}

var thd apcThread

func init() {
	thd.init()
}

func (t *apcThread) nextWaitTimeout() uint32 {
	if len(t.pending) > 0 {
		return windows.INFINITE
	} else {
		return noPendingIdleTimeout
	}
}

func (t *apcThread) beginRequest(req APCRequest) {
	// Lock the OS thread before calling Begin, which will initiate the APC
	// request on the current OS thread.
	runtime.LockOSThread()
	apcctx := req.Begin()
	if apcctx == nil {
		// Request failed, we don't need to lock anymore.
		runtime.UnlockOSThread()
	} else {
		// Save the context so it doesn't get GC'd and we can track pending requests
		t.pending[apcctx] = struct{}{}
	}
}

// run is the goroutine that executes APC requests. It is started lazily, but
// once it is running, it remains so for the remainder of the process's lifetime.
// Note that it only locks the OS thread while requests are in-flight; once
// all requests have been processed, it blocks on t.reqChan without consuming
// an OS thread.
// (Hi Brad! When this goroutine is 100% idle, it does not lock an OS thread.
// Is this acceptable, or do we want additional magic to make the
// entire goroutine shut down after an extended period of disuse?)
func (t *apcThread) run() {
	for {
		select {
		case req := <-t.reqChan:
			t.beginRequest(req)
			continue
		default:
			// If nothing is pending, we can safely block indefinitely on the request channel.
			// Otherwise we need to fall through into blocking on t.event so that we may process APCs.
			if len(t.pending) == 0 {
				req := <-t.reqChan
				t.beginRequest(req)
				continue
			}
		}

		var waitCode uint32
		var err error
		for waitCode, err = waitForSingleObjectEx(t.event, t.nextWaitTimeout(), true); waitCode == windows.WAIT_IO_COMPLETION; {
			// Drain queued APCs
		}
		switch waitCode {
		case uint32(windows.WAIT_TIMEOUT):
			// There are no more requests pending, we can just block on t.reqChan now
			continue
		case uint32(windows.WAIT_FAILED):
			panic(fmt.Sprintf("apcThread waitForSingleObjectEx failed: %v", err))
		default:
			// There are new requests in the channel.
			windows.ResetEvent(t.event)
			continue
		}
	}
}

type apcHandler func([]reflect.Value) []reflect.Value

// makeAPCHandler creates a handler function that an APC will invoke to complete
// its request. args contains the APC's arguments, which are then sent to the
// channel for processing by the API consumer.
func (t *apcThread) makeAPCHandler(resolver APCChannelResolver) apcHandler {
	return func(args []reflect.Value) []reflect.Value {
		apcchan := resolver.GetChannel(args)
		delete(t.pending, apcchan)
		runtime.UnlockOSThread()
		*apcchan <- args
		// APCs don't use return values, but we need to return this to satisfy
		// Go's callback requirements.
		return []reflect.Value{reflect.ValueOf(uintptr(0))}
	}
}

func (t *apcThread) registerCallback(cb APCCallbackInfo) uintptr {
	// Common path: Callback is already registered
	t.mu.RLock()
	cookie, ok := t.cbinfo[cb]
	t.mu.RUnlock()
	if ok {
		return cookie
	}

	// Slower path: We need to register
	t.mu.Lock()
	// Check again to make sure we didn't lose a race
	cookie, ok = t.cbinfo[cb]
	if ok {
		t.mu.Unlock()
		return cookie
	}

	handler := t.makeAPCHandler(cb.Resolver)
	outer := reflect.MakeFunc(cb.Function, handler)
	cbptr := windows.NewCallback(outer.Interface())
	t.cbinfo[cb] = cbptr
	t.mu.Unlock()
	return cbptr
}

// RegisterAPCCallback must be called any time a new type of APC is going to be
// submitted. Ideally this would be called only once for each type (via sync.Once).
func RegisterAPCCallback(cb APCCallbackInfo) uintptr {
	return thd.registerCallback(cb)
}

// SubmitAPCWork is the main entry point for submitting work for APC processing.
// The APC type must have been previously registered via RegisterAPICallback.
func SubmitAPCWork(req APCRequest) error {
	return thd.submitWork(req)
}
