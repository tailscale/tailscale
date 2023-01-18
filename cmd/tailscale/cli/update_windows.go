// Copyright (c) 2023 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Windows-specific stuff that can't go in update.go because it needs
// x/sys/windows.

package cli

import (
	"golang.org/x/sys/windows"
)

func init() {
	markTempFileFunc = markTempFileWindows
}

func markTempFileWindows(name string) error {
	name16 := windows.StringToUTF16Ptr(name)
	return windows.MoveFileEx(name16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
