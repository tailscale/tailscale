// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package paths

import (
	"path/filepath"

	"golang.org/x/sys/unix"
)

func init() {
	stateFileFunc = stateFileUnix
}

func stateFileUnix() string {
	// TODO: use other default paths on other GOOSes probably. This works for Linux.
	const varLib = "/var/lib/tailscale/tailscaled.state"
	try := varLib
	for i := 0; i < 3; i++ { // check writability of the file, /var/lib/tailscale, and /var/lib
		err := unix.Access(try, unix.O_RDWR)
		if err == nil {
			return varLib
		}
		try = filepath.Dir(try)
	}

	// TODO: try some $HOME/.tailscale or XDG path? But will it
	// even work usefully enough as non-root? Probably not. Maybe
	// best to require it be explicit in that case.
	return ""
}
