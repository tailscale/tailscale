// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"log"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const regBase = `SOFTWARE\Tailscale IPN`

// GetDesktopPID searches the PID of the process that's running the
// currently active desktop and whether it was found.
// Usually the PID will be for explorer.exe.
func GetDesktopPID() (pid uint32, ok bool) {
	hwnd := windows.GetShellWindow()
	if hwnd == 0 {
		return 0, false
	}
	windows.GetWindowThreadProcessId(hwnd, &pid)
	return pid, pid != 0
}

func getRegString(name, defval string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, RegBase, registry.READ)
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", RegBase, err)
		return defval
	}
	defer key.Close()

	val, _, err := key.GetStringValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.GetStringValue(%v): %v", name, err)
		}
		return defval
	}
	return val
}

func getRegInteger(name string, defval uint64) uint64 {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, RegBase, registry.READ)
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", RegBase, err)
		return defval
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.GetIntegerValue(%v): %v", name, err)
		}
		return defval
	}
	return val
}

var (
	kernel32                         = syscall.NewLazyDLL("kernel32.dll")
	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
)

// TODO(crawshaw): replace with x/sys/windows... one day.
// https://go-review.googlesource.com/c/sys/+/331909
func WTSGetActiveConsoleSessionId() uint32 {
	r1, _, _ := procWTSGetActiveConsoleSessionId.Call()
	return uint32(r1)
}

func isSIDValidPrincipal(uid string) bool {
	usid, err := syscall.StringToSid(uid)
	if err != nil {
		return false
	}

	_, _, accType, err := usid.LookupAccount("")
	if err != nil {
		return false
	}

	switch accType {
	case syscall.SidTypeUser, syscall.SidTypeGroup, syscall.SidTypeDomain, syscall.SidTypeAlias, syscall.SidTypeWellKnownGroup, syscall.SidTypeComputer:
		return true
	default:
		// Reject deleted users, invalid SIDs, unknown SIDs, mandatory label SIDs, etc.
		return false
	}
}
