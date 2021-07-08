package uring

// #cgo CFLAGS: -I${SRCDIR}/liburing/src/include
// #cgo LDFLAGS: -L${SRCDIR}/liburing/src/ -luring
// #include "io_uring.c"
import "C"

import (
	"syscall"
	"unsafe"
)

// hasUring reports whether it is possible to use io_uring syscalls on the system.
func uringSupported() bool {
	probe, err := C.io_uring_get_probe()
	if err == nil && probe != nil {
		C.free(unsafe.Pointer(probe))
	}
	return err != syscall.ENOSYS
}
