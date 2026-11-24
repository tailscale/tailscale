// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlat

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
)

// addNetNS creates a named network namespace that is deleted when the test ends.
func addNetNS(t *testing.T, name string) netns.NsHandle {
	t.Helper()
	exec.Command("ip", "netns", "del", name).Run() // left over from an aborted run
	sh(t, "ip netns add "+name)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", name).Run() })
	h, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// inNS runs fn on an OS thread switched into ns. The thread stays locked, so the runtime discards it afterwards instead of reusing it in the wrong namespace. Sockets opened inside fn stay in ns.
func inNS(ns netns.NsHandle, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(ns); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

// sh runs a command line (split on spaces) and fails the test if it fails.
func sh(t *testing.T, cmdline string) string {
	t.Helper()
	f := strings.Fields(cmdline)
	out, err := exec.Command(f[0], f[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmdline, err, out)
	}
	return string(out)
}
