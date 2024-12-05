// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package permissions

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

func permissionsImpl(logf logger.Logf) error {
	// NOTE: getresuid and getresgid never fail unless passed an
	// invalid address.
	var ruid, euid, suid uint64
	unix.Syscall(unix.SYS_GETRESUID,
		uintptr(unsafe.Pointer(&ruid)),
		uintptr(unsafe.Pointer(&euid)),
		uintptr(unsafe.Pointer(&suid)),
	)

	var rgid, egid, sgid uint64
	unix.Syscall(unix.SYS_GETRESGID,
		uintptr(unsafe.Pointer(&rgid)),
		uintptr(unsafe.Pointer(&egid)),
		uintptr(unsafe.Pointer(&sgid)),
	)

	groups, _ := unix.Getgroups()

	var buf strings.Builder
	fmt.Fprintf(&buf, "ruid=%s euid=%s suid=%s rgid=%s egid=%s sgid=%s groups=%s",
		formatUserID(ruid), formatUserID(euid), formatUserID(suid),
		formatGroupID(rgid), formatGroupID(egid), formatGroupID(sgid),
		formatGroups(groups),
	)

	// Get process capabilities
	var (
		capHeader = unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
			Pid:     0, // 0 means 'ourselves'
		}
		capData unix.CapUserData
	)

	if err := unix.Capget(&capHeader, &capData); err != nil {
		fmt.Fprintf(&buf, " caperr=%v", err)
	} else {
		fmt.Fprintf(&buf, " cap_effective=%08x cap_permitted=%08x cap_inheritable=%08x",
			capData.Effective, capData.Permitted, capData.Inheritable,
		)
	}

	logf("%s", buf.String())
	return nil
}
