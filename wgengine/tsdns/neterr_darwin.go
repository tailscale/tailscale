// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"errors"
	"syscall"
)

func isSyscallErrno(err error, errno syscall.Errno) bool {
	var n syscall.Errno
	if !errors.As(err, &n) {
		return false
	}
	return n == errno
}

func networkIsDown(err error) bool {
	return isSyscallErrno(err, syscall.ENETDOWN)
}

func networkIsUnreachable(err error) bool {
	return isSyscallErrno(err, syscall.ENETUNREACH)
}
