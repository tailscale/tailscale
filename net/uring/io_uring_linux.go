package uring

// #cgo LDFLAGS: -luring
// #include "io_uring_linux.c"
import "C"

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"
)

// A writeRing is an io_uring usable for sendmsg or pwritev calls.
// It manages an array of re-usable buffers.
type writeRing struct {
	ring *C.go_uring
	// reqs is an array of re-usable write requests.
	// We dispatch them to the kernel as writes are requested.
	// The array length is tied to the size of the uring.
	reqs [8]*C.goreq
	// reqC is a channel containing indices into reqs
	// that are free to use (that is, not in the kernel).
	reqC chan int
}

// initReqs initializes r's reqs so that they can be used for writes/sends.
func (r *writeRing) initReqs(ipLen int) {
	for i := range &r.reqs {
		r.reqs[i] = C.initializeReq(bufferSize, C.size_t(i), C.int(ipLen))
	}
	r.reqC = make(chan int, len(r.reqs))
	for i := range r.reqs {
		r.reqC <- i
	}
}

// getReq gets a req usable for a write/send.
// It blocks until such a req is available.
func (r *writeRing) getReq() (req *C.goreq, err error) {
	var idx int
	select {
	case idx = <-r.reqC:
	default:
		// No request available. Get one from the kernel.
		n, idx, err := waitCompletion(r.ring)
		if err != nil {
			return nil, fmt.Errorf("Write io_uring call failed: %w", err)
		}
		if n < 0 {
			// Past syscall failed.
			r.reqC <- idx // don't leak idx
			return nil, fmt.Errorf("previous Write failed: %w", syscall.Errno(-n))
		}
	}
	return r.reqs[idx], nil
}

// prefetch attempts to fetch a req for use by future writes.
// It does not block.
func (r *writeRing) prefetch() {
	idx, ok := peekCompletion(r.ring)
	if ok {
		// Put the request buffer back in the usable queue.
		// Should never block, by construction.
		r.reqC <- idx
	}
}

// freeReqs frees the reqs allocated by initReqs.
func (r *writeRing) freeReqs() {
	for _, req := range r.reqs {
		C.freeReq(req)
	}
}

const (
	noBlockForCompletion = 0
	blockForCompletion   = 1
)

// waitCompletion blocks until a completion on ring succeeds, or until *fd == 0.
// If *fd == 0, that indicates that the ring is no loner valid, in which case waitCompletion returns net.ErrClosed.
// Reads of *fd are atomic.
func waitCompletion(ring *C.go_uring) (n, idx int, err error) {
	for {
		r := C.completion(ring, blockForCompletion)
		if syscall.Errno(-r.err) == syscall.EAGAIN || syscall.Errno(-r.err) == syscall.EINTR {
			continue
		}
		var err error
		if r.err < 0 {
			err = syscall.Errno(-r.err)
		}
		return int(r.n), int(r.idx), err
	}
}

func peekCompletion(ring *C.go_uring) (idx int, ok bool) {
	r := C.completion(ring, noBlockForCompletion)
	if r.err < 0 {
		return 0, false
	}
	return int(r.idx), true
}

// sliceOf returns ptr[:n] as a byte slice.
// TODO: replace with unsafe.Slice once we are using Go 1.17.
func sliceOf(ptr *C.char, n int) []byte {
	var b []byte
	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	h.Data = uintptr(unsafe.Pointer(ptr))
	h.Len = n
	h.Cap = n
	return b
}
