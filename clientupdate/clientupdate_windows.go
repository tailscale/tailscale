// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Windows-specific stuff that can't go in clientupdate.go because it needs
// x/sys/windows.

package clientupdate

import (
	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil/authenticode"
)

func init() {
	markTempFileFunc = markTempFileWindows
	verifyAuthenticode = verifyTailscale
}

func markTempFileWindows(name string) error {
	name16 := windows.StringToUTF16Ptr(name)
	return windows.MoveFileEx(name16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

const certSubjectTailscale = "Tailscale Inc."

func verifyTailscale(path string) error {
	return authenticode.Verify(path, certSubjectTailscale)
}
