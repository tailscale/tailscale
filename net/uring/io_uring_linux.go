package uring

// #cgo LDFLAGS: -luring
// #include "io_uring_linux.c"
import "C"

import (
	"reflect"
	"syscall"
	"unsafe"
)

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
		if syscall.Errno(-r.err) == syscall.EAGAIN {
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
