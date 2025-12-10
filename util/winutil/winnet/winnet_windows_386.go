// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winnet

import (
	"syscall"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

func (i *INetworkListManager) GetNetwork(networkID windows.GUID) (*INetwork, error) {
	words := (*[4]uintptr)(unsafe.Pointer(&networkID))
	var result *INetwork
	r, _, _ := syscall.SyscallN(
		i.VTable().GetNetwork,
		uintptr(unsafe.Pointer(i)),
		words[0],
		words[1],
		words[2],
		words[3],
		uintptr(unsafe.Pointer(&result)),
	)

	if int32(r) < 0 {
		return nil, ole.NewError(r)
	}

	return result, nil
}
