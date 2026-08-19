// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package tstest

import "os"

// hasSuperuserPrivileges reports whether the current process runs as root.
func hasSuperuserPrivileges() bool { return os.Getuid() == 0 }
