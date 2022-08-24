// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !(386 || loong64)

package linuxfw

import (
	"testing"
	"unsafe"

	"tailscale.com/util/linuxfw/linuxfwtest"
)

func TestSizes(t *testing.T) {
	linuxfwtest.TestSizes(t, &linuxfwtest.SizeInfo{
		SizeofSocklen: unsafe.Sizeof(sockLen(0)),
	})
}
