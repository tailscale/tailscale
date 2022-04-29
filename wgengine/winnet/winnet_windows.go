// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
