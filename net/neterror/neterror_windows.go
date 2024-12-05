// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"

	"golang.org/x/sys/windows"
)

func init() {
	packetWasTruncated = func(err error) bool {
		return errors.Is(err, windows.WSAEMSGSIZE)
	}
}
