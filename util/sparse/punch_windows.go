// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package sparse

import (
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// punchAt for Windows also marks the file as sparse before it punches a hole in it.
func punchAt(fd *os.File, off, size int64) error {
	// Windows is unique in that if you call FSCTL_SET_ZERO_DATA on a non sparse file it will just zero out the hole.
	// Ensure the file is marked as sparse before punching a hole.
	// Docs: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_zero_data#remarks
	err := markAsSparseFile(fd)
	if err != nil {
		return &fs.PathError{Op: "punchAt", Path: fd.Name(), Err: err}
	}
	fileHandle := syscall.Handle(fd.Fd())

	// https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-file_zero_data_information
	zeroData := struct {
		FileOffset      uint64
		ByeondFinalZero uint64
	}{
		FileOffset:      uint64(off),
		ByeondFinalZero: uint64(off + size),
	}

	var bytesReturned uint32
	err = syscall.DeviceIoControl(fileHandle, windows.FSCTL_SET_ZERO_DATA, (*byte)(unsafe.Pointer(&zeroData)), uint32(unsafe.Sizeof(zeroData)), nil, 0, &bytesReturned, nil)
	if err != nil {
		return &fs.PathError{Op: "punchAt", Path: fd.Name(), Err: err}
	}
	return err
}

func markAsSparseFile(file *os.File) error {
	fileHandle := syscall.Handle(file.Fd())

	var bytesReturned uint32
	// FSCTL_SET_SPARSE is the windows syscall to mark a file as sparse.
	// Docs: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_sparse
	return syscall.DeviceIoControl(fileHandle, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &bytesReturned, nil)
}
