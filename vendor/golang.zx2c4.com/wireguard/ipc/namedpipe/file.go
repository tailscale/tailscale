// Copyright 2021 The Go Authors. All rights reserved.
// Copyright 2015 Microsoft
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package namedpipe

import (
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type timeoutChan chan struct{}

var ioInitOnce sync.Once
var ioCompletionPort windows.Handle

// ioResult contains the result of an asynchronous IO operation
type ioResult struct {
	bytes uint32
	err   error
}

// ioOperation represents an outstanding asynchronous Win32 IO
type ioOperation struct {
	o  windows.Overlapped
	ch chan ioResult
}

func initIo() {
	h, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
	if err != nil {
		panic(err)
	}
	ioCompletionPort = h
	go ioCompletionProcessor(h)
}

// file implements Reader, Writer, and Closer on a Win32 handle without blocking in a syscall.
// It takes ownership of this handle and will close it if it is garbage collected.
type file struct {
	handle        windows.Handle
	wg            sync.WaitGroup
	wgLock        sync.RWMutex
	closing       uint32 // used as atomic boolean
	socket        bool
	readDeadline  deadlineHandler
	writeDeadline deadlineHandler
}

type deadlineHandler struct {
	setLock     sync.Mutex
	channel     timeoutChan
	channelLock sync.RWMutex
	timer       *time.Timer
	timedout    uint32 // used as atomic boolean
}

// makeFile makes a new file from an existing file handle
func makeFile(h windows.Handle) (*file, error) {
	f := &file{handle: h}
	ioInitOnce.Do(initIo)
	_, err := windows.CreateIoCompletionPort(h, ioCompletionPort, 0, 0)
	if err != nil {
		return nil, err
	}
	err = windows.SetFileCompletionNotificationModes(h, windows.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS|windows.FILE_SKIP_SET_EVENT_ON_HANDLE)
	if err != nil {
		return nil, err
	}
	f.readDeadline.channel = make(timeoutChan)
	f.writeDeadline.channel = make(timeoutChan)
	return f, nil
}

// closeHandle closes the resources associated with a Win32 handle
func (f *file) closeHandle() {
	f.wgLock.Lock()
	// Atomically set that we are closing, releasing the resources only once.
	if atomic.SwapUint32(&f.closing, 1) == 0 {
		f.wgLock.Unlock()
		// cancel all IO and wait for it to complete
		windows.CancelIoEx(f.handle, nil)
		f.wg.Wait()
		// at this point, no new IO can start
		windows.Close(f.handle)
		f.handle = 0
	} else {
		f.wgLock.Unlock()
	}
}

// Close closes a file.
func (f *file) Close() error {
	f.closeHandle()
	return nil
}

// prepareIo prepares for a new IO operation.
// The caller must call f.wg.Done() when the IO is finished, prior to Close() returning.
func (f *file) prepareIo() (*ioOperation, error) {
	f.wgLock.RLock()
	if atomic.LoadUint32(&f.closing) == 1 {
		f.wgLock.RUnlock()
		return nil, os.ErrClosed
	}
	f.wg.Add(1)
	f.wgLock.RUnlock()
	c := &ioOperation{}
	c.ch = make(chan ioResult)
	return c, nil
}

// ioCompletionProcessor processes completed async IOs forever
func ioCompletionProcessor(h windows.Handle) {
	for {
		var bytes uint32
		var key uintptr
		var op *ioOperation
		err := windows.GetQueuedCompletionStatus(h, &bytes, &key, (**windows.Overlapped)(unsafe.Pointer(&op)), windows.INFINITE)
		if op == nil {
			panic(err)
		}
		op.ch <- ioResult{bytes, err}
	}
}

// asyncIo processes the return value from ReadFile or WriteFile, blocking until
// the operation has actually completed.
func (f *file) asyncIo(c *ioOperation, d *deadlineHandler, bytes uint32, err error) (int, error) {
	if err != windows.ERROR_IO_PENDING {
		return int(bytes), err
	}

	if atomic.LoadUint32(&f.closing) == 1 {
		windows.CancelIoEx(f.handle, &c.o)
	}

	var timeout timeoutChan
	if d != nil {
		d.channelLock.Lock()
		timeout = d.channel
		d.channelLock.Unlock()
	}

	var r ioResult
	select {
	case r = <-c.ch:
		err = r.err
		if err == windows.ERROR_OPERATION_ABORTED {
			if atomic.LoadUint32(&f.closing) == 1 {
				err = os.ErrClosed
			}
		} else if err != nil && f.socket {
			// err is from Win32. Query the overlapped structure to get the winsock error.
			var bytes, flags uint32
			err = windows.WSAGetOverlappedResult(f.handle, &c.o, &bytes, false, &flags)
		}
	case <-timeout:
		windows.CancelIoEx(f.handle, &c.o)
		r = <-c.ch
		err = r.err
		if err == windows.ERROR_OPERATION_ABORTED {
			err = os.ErrDeadlineExceeded
		}
	}

	// runtime.KeepAlive is needed, as c is passed via native
	// code to ioCompletionProcessor, c must remain alive
	// until the channel read is complete.
	runtime.KeepAlive(c)
	return int(r.bytes), err
}

// Read reads from a file handle.
func (f *file) Read(b []byte) (int, error) {
	c, err := f.prepareIo()
	if err != nil {
		return 0, err
	}
	defer f.wg.Done()

	if atomic.LoadUint32(&f.readDeadline.timedout) == 1 {
		return 0, os.ErrDeadlineExceeded
	}

	var bytes uint32
	err = windows.ReadFile(f.handle, b, &bytes, &c.o)
	n, err := f.asyncIo(c, &f.readDeadline, bytes, err)
	runtime.KeepAlive(b)

	// Handle EOF conditions.
	if err == nil && n == 0 && len(b) != 0 {
		return 0, io.EOF
	} else if err == windows.ERROR_BROKEN_PIPE {
		return 0, io.EOF
	} else {
		return n, err
	}
}

// Write writes to a file handle.
func (f *file) Write(b []byte) (int, error) {
	c, err := f.prepareIo()
	if err != nil {
		return 0, err
	}
	defer f.wg.Done()

	if atomic.LoadUint32(&f.writeDeadline.timedout) == 1 {
		return 0, os.ErrDeadlineExceeded
	}

	var bytes uint32
	err = windows.WriteFile(f.handle, b, &bytes, &c.o)
	n, err := f.asyncIo(c, &f.writeDeadline, bytes, err)
	runtime.KeepAlive(b)
	return n, err
}

func (f *file) SetReadDeadline(deadline time.Time) error {
	return f.readDeadline.set(deadline)
}

func (f *file) SetWriteDeadline(deadline time.Time) error {
	return f.writeDeadline.set(deadline)
}

func (f *file) Flush() error {
	return windows.FlushFileBuffers(f.handle)
}

func (f *file) Fd() uintptr {
	return uintptr(f.handle)
}

func (d *deadlineHandler) set(deadline time.Time) error {
	d.setLock.Lock()
	defer d.setLock.Unlock()

	if d.timer != nil {
		if !d.timer.Stop() {
			<-d.channel
		}
		d.timer = nil
	}
	atomic.StoreUint32(&d.timedout, 0)

	select {
	case <-d.channel:
		d.channelLock.Lock()
		d.channel = make(chan struct{})
		d.channelLock.Unlock()
	default:
	}

	if deadline.IsZero() {
		return nil
	}

	timeoutIO := func() {
		atomic.StoreUint32(&d.timedout, 1)
		close(d.channel)
	}

	now := time.Now()
	duration := deadline.Sub(now)
	if deadline.After(now) {
		// Deadline is in the future, set a timer to wait
		d.timer = time.AfterFunc(duration, timeoutIO)
	} else {
		// Deadline is in the past. Cancel all pending IO now.
		timeoutIO()
	}
	return nil
}
