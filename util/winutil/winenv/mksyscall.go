// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package winenv

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go mksyscall.go

// https://web.archive.org/web/20240407040123/https://learn.microsoft.com/en-us/windows/win32/api/mdmregistration/nf-mdmregistration-isdeviceregisteredwithmanagement
//sys isDeviceRegisteredWithManagement(isMDMRegistered *bool, upnBufLen uint32, upnBuf *uint16) (hr int32, err error) = MDMRegistration.IsDeviceRegisteredWithManagement?

// https://web.archive.org/web/20240407035921/https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow
//sys verifyVersionInfo(verInfo *osVersionInfoEx, typ verTypeMask, cond verCondMask) (res bool) = kernel32.VerifyVersionInfoW

// https://web.archive.org/web/20240407035706/https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-versetconditionmask
//sys verSetConditionMask(condMask verCondMask, typ verTypeMask, cond verCond) (res verCondMask) = kernel32.VerSetConditionMask
