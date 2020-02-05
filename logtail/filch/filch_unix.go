// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build !windows

package filch

import (
	"os"
	"syscall"
)

func saveStderr() (*os.File, error) {
	fd, err := syscall.Dup(stderrFD)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "stderr"), nil
}

func unsaveStderr(f *os.File) error {
	err := dup2Stderr(f)
	f.Close()
	return err
}

func dup2Stderr(f *os.File) error {
	return syscall.Dup2(int(f.Fd()), stderrFD)
}
