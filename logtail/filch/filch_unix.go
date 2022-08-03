// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows && !js
// +build !windows,!js

package filch

import (
	"os"

	"golang.org/x/sys/unix"
)

func saveStderr() (*os.File, error) {
	fd, err := unix.Dup(stderrFD)
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
	return unix.Dup2(int(f.Fd()), stderrFD)
}
