package uring

// #cgo LDFLAGS: -luring
// #include "io_uring_linux.c"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"tailscale.com/syncs"
)

// A file is a file handle that uses io_uring for reads and writes.
// It is intended for use with TUN fds, and thus only supports
// reading from and writing to file offset 0.
type file struct {
	// We have two urings so that we don't have to demux completion events.

	// writeRing is the uring for pwritev calls.
	writeRing writeRing
	// readRing is the uring for preadv calls.
	readRing *C.go_uring

	// close ensures that file closes occur exactly once.
	close sync.Once
	// closed indicates whether the file has been closed.
	closed syncs.AtomicBool
	// shutdown is a sequence of funcs to be called when the UDPConn closes.
	shutdown []func()

	// file is the os file underlying this file.
	file *os.File

	// readReqs is an array of re-usable file preadv requests.
	// We attempt to keep them all queued up for the kernel to fulfill.
	// The array length is tied to the size of the uring.
	readReqs [1]*C.goreq // Whoops! The kernel apparently cannot handle more than 1 concurrent preadv calls on a tun device!

	// refcount counts the number of outstanding read/write requests.
	// See the length comment for UDPConn.refcount for details.
	refcount syncs.AtomicInt32
}

func newFile(f *os.File) (*file, error) {
	u := &file{
		readRing: new(C.go_uring),
		file:     f,
	}
	u.writeRing.ring = new(C.go_uring)

	fd := f.Fd()
	if ret := C.initialize(u.readRing, C.int(fd)); ret < 0 {
		u.doShutdown()
		return nil, fmt.Errorf("readRing initialization failed: %w", syscall.Errno(-ret))
	}
	u.shutdown = append(u.shutdown, func() {
		C.io_uring_queue_exit(u.readRing)
	})

	if ret := C.initialize(u.writeRing.ring, C.int(fd)); ret < 0 {
		u.doShutdown()
		return nil, fmt.Errorf("writeRing initialization failed: %w", syscall.Errno(-ret))
	}
	u.shutdown = append(u.shutdown, func() {
		C.io_uring_queue_exit(u.writeRing.ring)
	})

	// Initialize buffers
	for i := range &u.readReqs {
		u.readReqs[i] = C.initializeReq(bufferSize, C.size_t(i), 0) // 0: not used for IP addresses
	}
	u.writeRing.initReqs(0) // 0: not used for IP addresses
	u.shutdown = append(u.shutdown, func() {
		for _, r := range u.readReqs {
			C.freeReq(r)
		}
		u.writeRing.freeReqs()
	})

	// Initialize read half.
	for i := range u.readReqs {
		if err := u.submitReadvRequest(i); err != nil {
			u.doShutdown()
			return nil, err
		}
	}

	// Initialization succeeded.
	// Take ownership of the file.
	u.shutdown = append(u.shutdown, func() {
		u.file.Close()
	})
	return u, nil
}

func (u *file) submitReadvRequest(idx int) error {
	errno := C.submit_readv_request(u.readRing, u.readReqs[idx])
	if errno < 0 {
		return fmt.Errorf("uring.submitReadvRequest failed: %w", syscall.Errno(-errno))
	}
	atomic.AddInt32(u.readReqInKernel(idx), 1) // TODO: CAS?
	return nil
}

func (u *file) readReqInKernel(idx int) *int32 {
	return (*int32)(unsafe.Pointer(&u.readReqs[idx].in_kernel))
}

// Read data into buf.
func (u *file) Read(buf []byte) (n int, err error) {
	// The docs for the u.refcount field document this prologue.
	u.refcount.Add(1)
	defer u.refcount.Add(-1)
	if u.closed.Get() {
		return 0, os.ErrClosed
	}

	n, idx, err := waitCompletion(u.readRing)
	if errors.Is(err, syscall.ECANCELED) {
		atomic.AddInt32(u.readReqInKernel(idx), -1)
		return 0, os.ErrClosed
	}
	if err != nil {
		return 0, fmt.Errorf("Read: io_uring failed to issue syscall: %w", err)
	}
	atomic.AddInt32(u.readReqInKernel(idx), -1)
	if n < 0 {
		// io_uring ran our syscall, which failed.
		// Best effort attempt not to leak idx.
		u.submitReadvRequest(int(idx))
		return 0, fmt.Errorf("Read: syscall failed: %w", syscall.Errno(-n))
	}
	// Success.
	r := u.readReqs[idx]
	rbuf := sliceOf(r.buf, n)
	copy(buf, rbuf)
	// Queue up a new request.
	if err := u.submitReadvRequest(int(idx)); err != nil {
		// Aggressively return this error.
		return 0, err
	}
	return n, nil
}

func (u *file) Write(buf []byte) (int, error) {
	// The docs for the u.refcount field document this prologue.
	u.refcount.Add(1)
	defer u.refcount.Add(-1)
	if u.closed.Get() {
		return 0, os.ErrClosed
	}

	// Get a req, blocking as needed.
	r, err := u.writeRing.getReq()
	if err != nil {
		return 0, err
	}
	// Do the write.
	rbuf := sliceOf(r.buf, len(buf))
	copy(rbuf, buf)
	C.submit_writev_request(u.writeRing.ring, r, C.int(len(buf)))
	// Get an extra buffer, if available.
	u.writeRing.prefetch()
	return len(buf), nil
}

func (u *file) Close() error {
	u.close.Do(func() {
		// Announce to readers and writers that we are closing down.
		// Busy loop until all reads and writes are unblocked.
		// See the docs for u.refcount.
		u.closed.Set(true)
		for {
			// Request that the kernel cancel all submitted reads. (Writes don't block indefinitely.)
			for idx := range u.readReqs {
				if atomic.LoadInt32(u.readReqInKernel(idx)) != 0 {
					C.submit_cancel_request(u.readRing, C.size_t(idx))
				}
			}
			if u.refcount.Get() == 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		// Do the rest of the shutdown.
		u.doShutdown()
	})
	return nil
}

func (u *file) doShutdown() {
	for _, fn := range u.shutdown {
		fn()
	}
}
