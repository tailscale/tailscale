// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !windows && !darwin

package netns

import (
	"syscall"

	"tailscale.com/types/logger"
)

func control(logger.Logf) func(network, address string, c syscall.RawConn) error {
	return controlC
}

// controlC does nothing to c.
func controlC(network, address string, c syscall.RawConn) error {
	return nil
}
