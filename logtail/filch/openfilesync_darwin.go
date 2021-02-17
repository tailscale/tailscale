// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build darwin

package filch

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openFileSync(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	_, err = unix.FcntlInt(uintptr(f.Fd()), syscall.F_NOCACHE, 1)
	if err != nil {
		return nil, fmt.Errorf("openFileSync: %w", err)
	}
	return f, nil
}
