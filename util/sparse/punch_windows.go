// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package sparse

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// punchAt for Windows also marks the file as sparse before it punches a hole in it.
func punchAt(fd *os.File, off, size int64) error {
	err := markAsSparseFile(fd)
	if err != nil {
		return err
	}
	fileHandle := syscall.Handle(fd.Fd())

	zeroData := struct {
		Offset           uint64
		ByeondFinalZerop uint64
	}{
		Offset:           uint64(off),
		ByeondFinalZerop: uint64(off + size),
	}

	var bytesReturned uint32
	return syscall.DeviceIoControl(fileHandle, windows.FSCTL_SET_ZERO_DATA, (*byte)(unsafe.Pointer(&zeroData)), uint32(unsafe.Sizeof(zeroData)), nil, 0, &bytesReturned, nil)
}

func markAsSparseFile(file *os.File) error {
	fileHandle := syscall.Handle(file.Fd())

	var bytesReturned uint32

	return syscall.DeviceIoControl(fileHandle, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &bytesReturned, nil)
}
