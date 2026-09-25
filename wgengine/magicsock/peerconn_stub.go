// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !((linux && !android) || (darwin && !ios))

package magicsock

import (
	"errors"
	"syscall"

	"tailscale.com/types/logger"
)

func setReusePort(rc syscall.RawConn) error {
	return errors.ErrUnsupported
}

func peerConnSupported(logf logger.Logf) bool {
	return false
}
