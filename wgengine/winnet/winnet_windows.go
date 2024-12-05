// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winnet

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
)

func (v *INetworkConnection) GetAdapterId() (string, error) {
	buf := ole.GUID{}
	hr, _, _ := syscall.Syscall(
		v.VTable().GetAdapterId,
		2,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(&buf)),
		0)
	if hr != 0 {
		return "", fmt.Errorf("GetAdapterId failed: %08x", hr)
	}
	return buf.String(), nil
}
