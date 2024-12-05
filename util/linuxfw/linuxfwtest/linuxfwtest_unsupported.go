// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !cgo || !linux

package linuxfwtest

import (
	"testing"
)

type SizeInfo struct {
	SizeofSocklen uintptr
}

func TestSizes(t *testing.T, si *SizeInfo) {
	t.Skip("not supported without cgo")
}
