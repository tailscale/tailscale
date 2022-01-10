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

const (
	regBase       = `SOFTWARE\Tailscale IPN`
	regPolicyBase = `SOFTWARE\Policies\Tailscale`
)

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

func getPolicyString(name, defval string) string {
	s, err := getRegStringInternal(regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegString(name, defval)
	}
	return s
}

func getPolicyInteger(name string, defval uint64) uint64 {
	i, err := getRegIntegerInternal(regPolicyBase, name)
	if err != nil {
		// Fall back to the legacy path
		return getRegInteger(name, defval)
	}
	return i
}

func getRegString(name, defval string) string {
	s, err := getRegStringInternal(regBase, name)
	if err != nil {
		return defval
	}
	return s
}

func getRegInteger(name string, defval uint64) uint64 {
	i, err := getRegIntegerInternal(regBase, name)
	if err != nil {
		return defval
	}
	return i
}

func getRegStringInternal(subKey, name string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", subKey, err)
		return "", err
	}
	defer key.Close()

	val, _, err := key.GetStringValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.GetStringValue(%v): %v", name, err)
		}
		return "", err
	}
	return val, nil
}

func getRegIntegerInternal(subKey, name string) (uint64, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, subKey, registry.READ)
	if err != nil {
		log.Printf("registry.OpenKey(%v): %v", subKey, err)
		return 0, err
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		if err != registry.ErrNotExist {
			log.Printf("registry.GetIntegerValue(%v): %v", name, err)
		}
		return 0, err
	}
	return val, nil
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
