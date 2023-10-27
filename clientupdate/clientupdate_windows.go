// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Windows-specific stuff that can't go in clientupdate.go because it needs
// x/sys/windows.

package clientupdate

import (
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/authenticode"
)

func init() {
	markTempFileFunc = markTempFileWindows
	verifyAuthenticode = verifyTailscale
	launchTailscaleAsWinGUIUser = launchTailscaleAsGUIUser
}

func markTempFileWindows(name string) error {
	name16 := windows.StringToUTF16Ptr(name)
	return windows.MoveFileEx(name16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

const certSubjectTailscale = "Tailscale Inc."

func verifyTailscale(path string) error {
	return authenticode.Verify(path, certSubjectTailscale)
}

func launchTailscaleAsGUIUser(exePath string) error {
	exePath = filepath.Join(filepath.Dir(exePath), "tailscale-ipn.exe")

	var token windows.Token
	if u, err := user.Current(); err == nil && u.Name == "SYSTEM" {
		sessionID := winutil.WTSGetActiveConsoleSessionId()
		if sessionID != 0xFFFFFFFF {
			if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
				return err
			}
			defer token.Close()
		}
	}

	cmd := exec.Command(exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:      syscall.Token(token),
		HideWindow: true,
	}
	return cmd.Start()
}
