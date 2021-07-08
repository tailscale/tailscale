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

	"golang.zx2c4.com/wireguard/device"
)

// A File is a write-only file fd manager.
// TODO: Support reads
// TODO: all the todos from UDPConn
type file struct {
	writeRing *C.go_uring
	readRing  *C.go_uring
	close     sync.Once
	file      *os.File // must keep file from being GC'd
	fd        uintptr
	readReqs  [1]*C.goreq // Whoops! The kernel apparently cannot handle more than 1 concurrent preadv calls on a tun device!
	writeReqs [8]*C.goreq
	writeReqC chan int // indices into reqs
}

func newFile(f *os.File) (*file, error) {
	fd := f.Fd()
	u := &file{
		file: f,
		fd:   fd,
	}
	for _, ringPtr := range []**C.go_uring{&u.writeRing, &u.readRing} {
		r := new(C.go_uring)
		ret := C.initialize(r, C.int(fd))
		if ret < 0 {
			// TODO: handle unwinding partial initialization
			return nil, fmt.Errorf("uring initialization failed: %d", ret)
		}
		*ringPtr = r
	}

	// Initialize buffers
	for i := range &u.readReqs {
		u.readReqs[i] = C.initializeReq(bufferSize, 0)
	}
	for i := range &u.writeReqs {
		u.writeReqs[i] = C.initializeReq(bufferSize, 0)
	}

	// Initialize read half.
	for i := range u.readReqs {
		if err := u.submitReadvRequest(i); err != nil {
			u.Close() // TODO: will this crash?
			return nil, err
		}
	}

	u.writeReqC = make(chan int, len(u.writeReqs))
	for i := range u.writeReqs {
		u.writeReqC <- i
	}
	return u, nil
}

func (u *file) submitReadvRequest(idx int) error {
	// TODO: make a C struct instead of a Go struct, and pass that in, to simplify call sites.
	errno := C.submit_readv_request(u.readRing, u.readReqs[idx], C.size_t(idx))
	if errno < 0 {
		return fmt.Errorf("uring.submitReadvRequest failed: %v", errno) // TODO: Improve
	}
	return nil
}

type fileReq struct {
	iov C.go_iovec
	buf [device.MaxSegmentSize]byte
}

// Read data into buf[offset:].
// We are allowed to write junk into buf[offset-4:offset].
func (u *file) Read(buf []byte) (n int, err error) { // read a packet from the device (without any additional headers)
	if u.fd == 0 { // TODO: review all uses of u.fd for atomic read/write
		return 0, errors.New("invalid uring.File")
	}
	n, idx, err := waitCompletion(u.readRing)
	if err != nil {
		return 0, fmt.Errorf("Read: io_uring failed to issue syscall: %w", err)
	}
	if n < 0 {
		// Syscall failed.
		u.submitReadvRequest(int(idx)) // best effort attempt not to leak idx
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
	if u.fd == 0 {
		return 0, errors.New("invalid uring.FileConn")
	}
	// If we need a buffer, get a buffer, potentially blocking.
	var idx int
	select {
	case idx = <-u.writeReqC:
	default:
		// No request available. Get one from the kernel.
		n, idx, err := waitCompletion(u.writeRing)
		if err != nil {
			return 0, fmt.Errorf("Write io_uring call failed: %w", err)
		}
		if n < 0 {
			// Past syscall failed.
			u.writeReqC <- idx // don't leak idx
			return 0, fmt.Errorf("previous Write failed: %w", syscall.Errno(-n))
		}
	}
	r := u.writeReqs[idx]
	// Do the write.
	rbuf := sliceOf(r.buf, len(buf))
	copy(rbuf, buf)
	C.submit_writev_request(u.writeRing, r, C.int(len(buf)), C.size_t(idx))
	// Get an extra buffer, if available.
	idx, ok := peekCompletion(u.writeRing)
	if ok {
		// Put the request buffer back in the usable queue.
		// Should never block, by construction.
		u.writeReqC <- idx
	}
	return len(buf), nil
}

func (u *file) Close() error {
	u.close.Do(func() {
		atomic.StoreUintptr(&u.fd, 0)
		u.file.Close()
		u.file = nil
		// TODO: bring the shutdown logic from UDPConn.Close here?
		// Or is closing the file above enough, unlike for UDP?
		C.io_uring_queue_exit(u.readRing)
		C.io_uring_queue_exit(u.writeRing)

		// Free buffers
		for _, r := range u.readReqs {
			C.freeReq(r)
		}
		for _, r := range u.writeReqs {
			C.freeReq(r)
		}
	})
	return nil
}
