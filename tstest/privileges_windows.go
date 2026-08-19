// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package tstest

import "golang.org/x/sys/windows"

// hasSuperuserPrivileges reports whether the current process is elevated.
func hasSuperuserPrivileges() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
