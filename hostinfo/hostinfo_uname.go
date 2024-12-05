// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || freebsd || openbsd || darwin

package hostinfo

import (
	"runtime"

	"golang.org/x/sys/unix"
	"tailscale.com/types/ptr"
)

func init() {
	unameMachine = lazyUnameMachine.Get
}

var lazyUnameMachine = &lazyAtomicValue[string]{f: ptr.To(unameMachineUnix)}

func unameMachineUnix() string {
	switch runtime.GOOS {
	case "android":
		// Don't call on Android for now. We're late in the 1.36 release cycle
		// and don't want to test syscall filters on various Android versions to
		// see what's permitted. Notably, the hostinfo_linux.go file has build
		// tag !android, so maybe Uname is verboten.
		return ""
	case "ios":
		// For similar reasons, don't call on iOS. There aren't many iOS devices
		// and we know their CPU properties so calling this is only risk and no
		// reward.
		return ""
	}
	var un unix.Utsname
	unix.Uname(&un)
	return unix.ByteSliceToString(un.Machine[:])
}
