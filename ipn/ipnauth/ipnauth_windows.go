// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/pidowner"
)

var (
	kernel32                        = syscall.NewLazyDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = kernel32.NewProc("GetNamedPipeClientProcessId")
)

func getNamedPipeClientProcessId(h windows.Handle) (pid uint32, err error) {
	r1, _, err := procGetNamedPipeClientProcessId.Call(uintptr(h), uintptr(unsafe.Pointer(&pid)))
	if r1 > 0 {
		return pid, nil
	}
	return 0, err
}

// GetConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
// If c is not backed by a named pipe, an error is returned.
func GetConnIdentity(logf logger.Logf, c net.Conn) (ci *ConnIdentity, err error) {
	ci = &ConnIdentity{conn: c}
	h, ok := c.(interface {
		Fd() uintptr
	})
	if !ok {
		return ci, fmt.Errorf("not a windows handle: %T", c)
	}
	pid, err := getNamedPipeClientProcessId(windows.Handle(h.Fd()))
	if err != nil {
		return ci, fmt.Errorf("getNamedPipeClientProcessId: %v", err)
	}
	ci.pid = int(pid)
	uid, err := pidowner.OwnerOfPID(ci.pid)
	if err != nil {
		return ci, fmt.Errorf("failed to map connection's pid to a user (WSL?): %w", err)
	}
	ci.userID = ipn.WindowsUserID(uid)
	u, err := LookupUserFromID(logf, uid)
	if err != nil {
		return ci, fmt.Errorf("failed to look up user from userid: %w", err)
	}
	ci.user = u
	return ci, nil
}
