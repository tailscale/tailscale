// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package feature

import (
	"runtime"

	"tailscale.com/feature/buildfeatures"
)

// HookSystemdReady sends a readiness to systemd. This will unblock service
// dependents from starting.
var HookSystemdReady Hook[func()]

// HookSystemdStatus holds a func that will send a single line status update to
// systemd so that information shows up in systemctl output.
var HookSystemdStatus Hook[func(format string, args ...any)]

// SystemdStatus sends a single line status update to systemd so that
// information shows up in systemctl output.
//
// It does nothing on non-Linux systems or if the binary was built without
// the sdnotify feature.
func SystemdStatus(format string, args ...any) {
	if !CanSystemdStatus { // mid-stack inlining DCE
		return
	}
	if f, ok := HookSystemdStatus.GetOk(); ok {
		f(format, args...)
	}
}

// CanSystemdStatus reports whether the current build has systemd notifications
// linked in.
//
// It's effectively the same as HookSystemdStatus.IsSet(), but a constant for
// dead code elimination reasons.
const CanSystemdStatus = runtime.GOOS == "linux" && buildfeatures.HasSDNotify
