// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Windows-specific stuff that can't go in clientupdate.go because it needs
// x/sys/windows.

package clientupdate

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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
		sessionID, err := wtsGetActiveSessionID()
		if err != nil {
			return fmt.Errorf("wtsGetActiveSessionID(): %w", err)
		}
		if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
			return fmt.Errorf("WTSQueryUserToken (0x%x): %w", sessionID, err)
		}
		defer token.Close()
	}

	cmd := exec.Command(exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:      syscall.Token(token),
		HideWindow: true,
	}
	return cmd.Start()
}

func wtsGetActiveSessionID() (uint32, error) {
	var (
		sessionInfo *windows.WTS_SESSION_INFO
		count       uint32 = 0
	)

	const WTS_CURRENT_SERVER_HANDLE = 0
	if err := windows.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessionInfo, &count); err != nil {
		return 0, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessionInfo)))

	current := unsafe.Pointer(sessionInfo)
	for i := uint32(0); i < count; i++ {
		session := (*windows.WTS_SESSION_INFO)(current)
		if session.State == windows.WTSActive {
			return session.SessionID, nil
		}
		current = unsafe.Add(current, unsafe.Sizeof(windows.WTS_SESSION_INFO{}))
	}

	return 0, errors.New("no active desktop sessions found")
}
