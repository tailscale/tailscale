package uring

// #cgo CFLAGS: -I${SRCDIR}/liburing/src/include
// #cgo LDFLAGS: -L${SRCDIR}/liburing/src/ -luring
// #include "io_uring_linux.c"
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

// If/when we want to probe for specific io_uring capabilities,
// rather than just the presence of the syscalls,
// this code by Julian Knodt might be handy:
// https://gist.github.com/JulianKnodt/e7030739d163f5251eb47f8ac1d67b62
// (See discussion in https://github.com/tailscale/tailscale/pull/2371.)
