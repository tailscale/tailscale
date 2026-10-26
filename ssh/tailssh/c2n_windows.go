// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	hookLocalUsernames = windowsLocalUsernames
}

// userInfo1 is the Win32 USER_INFO_1 structure returned by NetUserEnum at
// level 1.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

const (
	// filterNormalAccount is NetUserEnum's FILTER_NORMAL_ACCOUNT: ordinary
	// user accounts, excluding machine and trust accounts.
	filterNormalAccount = 0x0002
	// ufAccountDisable is the UF_ACCOUNTDISABLE user flag.
	ufAccountDisable = 0x0002
	// maxPreferredLength asks NetUserEnum to allocate as much as it needs.
	maxPreferredLength = 0xFFFFFFFF
)

// windowsLocalUsernames returns the names of the enabled local user accounts
// on this machine.
func windowsLocalUsernames() ([]string, error) {
	var names []string
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 1, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return names, err
		}
		if buf != nil {
			for _, ui := range unsafe.Slice((*userInfo1)(unsafe.Pointer(buf)), read) {
				if ui.Flags&ufAccountDisable != 0 {
					continue
				}
				names = append(names, windows.UTF16PtrToString(ui.Name))
			}
			windows.NetApiBufferFree(buf)
		}
		if err == nil {
			return names, nil
		}
	}
}
