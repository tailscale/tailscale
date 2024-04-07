// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package winenv provides information about the current Windows environment.
// This includes details such as whether the device is a server or workstation,
// if it is AD domain-joined, MDM-registered, or neither, and other characteristics.
package winenv

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// osVersionInfoEx contains operating system version information.
// See [OSVERSIONINFOEXW] for details.
//
// [OSVERSIONINFOEXW]: https://web.archive.org/web/20240407035213/https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw
type osVersionInfoEx struct {
	cbSize           uint32
	majorVersion     uint32
	minorVersion     uint32
	buildNumber      uint32
	platformId       uint32
	csdVersion       [128]uint16
	servicePackMajor uint16
	servicePackMinor uint16
	suiteMask        uint16
	productType      verProductType
	reserved         uint8
}

type (
	verTypeMask    uint32
	verCondMask    uint64
	verCond        uint8
	verProductType uint8
)

// See [VER_SET_CONDITION] and [VerSetConditionMask] for details.
//
// [VER_SET_CONDITION]: https://web.archive.org/web/20240407035400/https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ver_set_condition
// [VerSetConditionMask]: https://web.archive.org/web/20240407035706/https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-versetconditionmask
const (
	_VER_MINORVERSION     = verTypeMask(0x0000001)
	_VER_MAJORVERSION     = verTypeMask(0x0000002)
	_VER_BUILDNUMBER      = verTypeMask(0x0000004)
	_VER_PLATFORMID       = verTypeMask(0x0000008)
	_VER_SERVICEPACKMINOR = verTypeMask(0x0000010)
	_VER_SERVICEPACKMAJOR = verTypeMask(0x0000020)
	_VER_SUITENAME        = verTypeMask(0x0000040)
	_VER_PRODUCT_TYPE     = verTypeMask(0x0000080)

	_VER_NT_WORKSTATION       = verProductType(1)
	_VER_NT_DOMAIN_CONTROLLER = verProductType(2)
	_VER_NT_SERVER            = verProductType(3)

	_VER_EQUAL         = verCond(1)
	_VER_GREATER       = verCond(2)
	_VER_GREATER_EQUAL = verCond(3)
	_VER_LESS          = verCond(4)
	_VER_LESS_EQUAL    = verCond(5)
	_VER_AND           = verCond(6)
	_VER_OR            = verCond(7)
)

// IsDomainJoined reports whether the device is domain-joined.
func IsDomainJoined() bool {
	var domain *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &domain, &status); err != nil {
		return false
	}
	windows.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	return status == windows.NetSetupDomainName
}

// IsMDMRegistered reports whether the device is MDM-registered.
func IsMDMRegistered() bool {
	const S_OK int32 = 0
	var isMDMRegistered bool
	if hr, err := isDeviceRegisteredWithManagement(&isMDMRegistered, 0, nil); err != nil || hr != S_OK {
		return false
	}
	return isMDMRegistered
}

// IsManaged reports whether the device is managed through AD or MDM.
func IsManaged() bool {
	return IsDomainJoined() || IsMDMRegistered()
}

// IsWindowsServer reports whether the device is running a Windows Server operating system.
func IsWindowsServer() bool {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		// TODO(nickkhyl): the Windows Server versions we support do not have 32-bit editions.
		// But we should remove this check once we adopt mkwinsyscallx, as it can handle 64-bit
		// long arguments such as verCondMask.
		return false
	}

	osvi := &osVersionInfoEx{
		cbSize:      uint32(unsafe.Sizeof(osVersionInfoEx{})),
		productType: _VER_NT_WORKSTATION,
	}
	condMask := verSetConditionMask(0, _VER_PRODUCT_TYPE, _VER_EQUAL)
	return !verifyVersionInfo(osvi, _VER_PRODUCT_TYPE, condMask)
}
