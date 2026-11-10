// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package ktimeout

import (
	"errors"
	"time"
)

// SetUserTimeout is a no-op on this platform.
func SetUserTimeout(fd uintptr, timeout time.Duration) error {
	return nil
}

func setUserTimeoutChecked(fd uintptr, timeout time.Duration) error {
	return errors.ErrUnsupported
}
