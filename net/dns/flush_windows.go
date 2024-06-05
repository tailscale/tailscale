// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func flushCaches() error {
	cmd := exec.Command("ipconfig", "/flushdns")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (output: %s)", err, out)
	}
	return nil
}

// Flush clears the local resolver cache.
//
// Only Windows has a public dns.Flush, needed in router_windows.go. Other
// platforms like Linux need a different flush implementation depending on
// the DNS manager. There is a FlushCaches method on the manager which
// can be used on all platforms.
func Flush() error {
	return flushCaches()
}
