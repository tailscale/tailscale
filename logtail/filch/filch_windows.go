// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package filch

import (
	"fmt"
	"os"
	"syscall"
)

var kernel32 = syscall.MustLoadDLL("kernel32.dll")
var procSetStdHandle = kernel32.MustFindProc("SetStdHandle")

func setStdHandle(stdHandle int32, handle syscall.Handle) error {
	r, _, e := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdHandle), uintptr(handle), 0)
	if r == 0 {
		if e != 0 {
			return error(e)
		}
		return syscall.EINVAL
	}
	return nil
}

func saveStderr() (*os.File, error) {
	return os.Stderr, nil
}

func unsaveStderr(f *os.File) error {
	os.Stderr = f
	return nil
}

func dup2Stderr(f *os.File) error {
	fd := int(f.Fd())
	err := setStdHandle(syscall.STD_ERROR_HANDLE, syscall.Handle(fd))
	if err != nil {
		return fmt.Errorf("dup2Stderr: %w", err)
	}
	os.Stderr = f
	return nil
}
