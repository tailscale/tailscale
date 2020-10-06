// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"net"
	"os"

	"golang.org/x/sys/windows"
)

func networkIsDown(err error) bool {
	if oe, ok := err.(*net.OpError); ok && oe.Op == "write" {
		if se, ok := oe.Err.(*os.SyscallError); ok {
			if se.Syscall == "wsasendto" && se.Err == windows.WSAENETUNREACH {
				return true
			}
		}
	}
	return false
}

func networkIsUnreachable(err error) bool {
	// TODO(bradfitz,josharian): something here? what is the
	// difference between down and unreachable? Add comments.
	return false
}
