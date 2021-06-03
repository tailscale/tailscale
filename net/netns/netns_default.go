// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !linux,!windows,!darwin darwin,ts_macext

package netns

import "syscall"

// control does nothing to c.
func control(network, address string, c syscall.RawConn) error {
	return nil
}
