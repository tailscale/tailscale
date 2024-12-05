// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd || openbsd

package permissions

import (
	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
)

func permissionsImpl(logf logger.Logf) error {
	groups, _ := unix.Getgroups()
	logf("uid=%s euid=%s gid=%s egid=%s groups=%s",
		formatUserID(unix.Getuid()),
		formatUserID(unix.Geteuid()),
		formatGroupID(unix.Getgid()),
		formatGroupID(unix.Getegid()),
		formatGroups(groups),
	)
	return nil
}
