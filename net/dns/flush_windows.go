// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"log"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"tailscale.com/util/coalescedop"
)

var (
	flushDNSOp    = coalescedop.New(doFlushDNS)
	registerDNSOp = coalescedop.New(doRegisterDNS)
)

func doFlushDNS() {
	t0 := time.Now()
	cmd := exec.Command("ipconfig", "/flushdns")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	err := cmd.Run()
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		log.Printf("error running ipconfig /flushdns after %v: %v", d, err)
	} else {
		log.Printf("ran ipconfig /flushdns in %v", d)
	}
}

func doRegisterDNS() {
	t0 := time.Now()
	cmd := exec.Command("ipconfig", "/registerdns")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	err := cmd.Run()
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		log.Printf("error running ipconfig /registerdns after %v: %v", d, err)
	} else {
		log.Printf("ran ipconfig /registerdns in %v", d)
	}
}

func flushCaches() error {
	flushDNSOp.Do()
	return nil
}

// Flush clears the local resolver cache.
//
// Only Windows has a public dns.Flush, needed in tailscaled_windows.go.
// Other platforms like Linux need a different flush implementation
// depending on the DNS manager. There is a FlushCaches method on the manager
// which can be used on all platforms.
//
// Flush is non-blocking; it coalesces concurrent and rapid successive
// calls so that at most one ipconfig /flushdns is in flight at a time,
// with at most one additional execution queued.
func Flush() {
	flushDNSOp.Do()
}

// registerDNS forces DNS re-registration in Active Directory. This
// invokes an undocumented hidden function that forces Windows to
// notice that adapter settings have changed, which makes the DNS
// settings actually take effect.
//
// registerDNS is non-blocking; it coalesces concurrent and rapid
// successive calls so that at most one ipconfig /registerdns is in
// flight at a time, with at most one additional execution queued.
func registerDNS() {
	registerDNSOp.Do()
}
