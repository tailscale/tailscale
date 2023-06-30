// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(#8502): add support for more architectures
//go:build linux && (arm64 || amd64)

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
