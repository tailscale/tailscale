// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && !386

package winnet

import (
	"syscall"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

func (i *INetworkListManager) GetNetwork(networkID windows.GUID) (*INetwork, error) {
	var result *INetwork
	r, _, _ := syscall.SyscallN(
		i.VTable().GetNetwork,
		uintptr(unsafe.Pointer(i)),
		uintptr(unsafe.Pointer(&networkID)),
		uintptr(unsafe.Pointer(&result)),
	)

	if int32(r) < 0 {
		return nil, ole.NewError(r)
	}

	return result, nil
}
