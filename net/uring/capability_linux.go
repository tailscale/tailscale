package uring

// #cgo CFLAGS: -I${SRCDIR}/liburing/src/include
// #cgo LDFLAGS: -L${SRCDIR}/liburing/src/ -luring
// #include "io_uring.c"
import "C"

import (
	"sync"
	"syscall"
	"unsafe"
)

type op = int

// https://unixism.net/loti/tutorial/probe_liburing.html
const (
	opNop op = iota
	opReadv
	opWritev
	opFsync
	opReadFixed
	opWriteFixed
	opPollAdd
	opPollRemove
	opSyncFileRange
	opSendMsg
	opRecvMsg
	opTimeout
	opTimeoutRemove
	opAccept
	opAsyncCancel
	opLinkTimeout
	opConnect
	opFAllocate
	opOpenAt
	opClose
	opFilesUpdate
	opStatx
	opRead
	opWrite
	opFAdvise
	opMAdvise
	opSend
	opRecv
	opOpenAt2
	opEPollControl
	opSplice
	opProvideBuffers
	opRemoveBuffers
	opCount
)

var (
	// probed ensures that capabilities is only populated once.
	probed sync.Once
	// capabilities is the list of available capabilities on this system
	capabilities map[op]bool
	// probingSupported is whether probing is available on this system.
	probingSupported bool
)

// checkCapability returns whether probing is supported, and if and only if probing is
// supported, whether the operation is also supported.
// If probing is not supported, it may still be the case that the operation can be used.
//
// To test for a specific operation if there is no probing, probably running it and seeing if
// the output is non-nil should be enough.
func checkCapability(o op) (probingSupported bool, opOk bool) {
	probed.Do(func() {
		probe, err := C.io_uring_get_probe()
		if probe == nil || err != nil {
			probingSupported = false
			return
		}
		capabilities = map[op]bool{}
		defer C.free(unsafe.Pointer(probe))
		for i := 0; i < opCount; i++ {
			capabilities[i] = C.io_uring_opcode_supported(probe, C.int(i)) != 0
		}
	})

	if !probingSupported {
		return false, false
	}
	return true, capabilities[o]
}

// uringOnSystem will check if it is possible to use io_uring syscalls on the system.
func uringOnSystem() bool {
	probe, err := C.io_uring_get_probe()
	if err == nil && probe != nil {
		C.free(unsafe.Pointer(probe))
	}
	return err != syscall.ENOSYS
}
