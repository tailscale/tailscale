// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/tstest"
)

// processWithMarkerRunning reports whether any process has marker in
// its command line. pgrep exits 1 for "no match", which is the only
// non-error "false" we accept.
func processWithMarkerRunning(t *testing.T, marker string) bool {
	t.Helper()
	err := exec.Command("pgrep", "-f", marker).Run()
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false
	}
	t.Fatalf("pgrep -f %q: %v", marker, err)
	return false
}

// TestSessionTerminationKillsHUPImmuneProcess asserts that a process
// which ignores SIGHUP still dies on session teardown. SIGHUP is the
// polite POSIX terminal-disconnect signal, but teardown can be policy
// (session recording failed and the policy says kill); a user command
// must not be able to outlive that by trapping HUP. tailssh escalates
// to SIGKILL on the process group after a grace period.
func TestSessionTerminationKillsHUPImmuneProcess(t *testing.T) {
	old := sessionKillGracePeriod
	sessionKillGracePeriod = time.Second
	t.Cleanup(func() { sessionKillGracePeriod = old })

	h := newTestSSHHarnessWithShell(t, "/bin/sh")

	marker := fmt.Sprintf("tailssh-hup-immune-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	// Same two-level shape as TestSessionTerminationKillsProcess, with
	// the grandchild ignoring HUP: only the SIGKILL escalation can
	// reap it.
	cmd := fmt.Sprintf(`/bin/sh -c 'trap "" HUP; while :; do sleep 1; done #%s' & wait`, marker)

	t.Cleanup(func() {
		exec.Command("pkill", "-9", "-f", marker).Run()
	})

	cl, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(cmd); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := tstest.WaitFor(10*time.Second, func() error {
		if !processWithMarkerRunning(t, marker) {
			return fmt.Errorf("marker process not started yet")
		}
		return nil
	}); err != nil {
		t.Fatalf("marker process never appeared: %v", err)
	}

	s.Close()
	cl.Close()

	if err := tstest.WaitFor(10*time.Second, func() error {
		if processWithMarkerRunning(t, marker) {
			return fmt.Errorf("process still running")
		}
		return nil
	}); err != nil {
		t.Fatalf("HUP-immune process survived session teardown: %v", err)
	}
}

// TestSessionTerminationKillsProcess asserts that tearing down an SSH
// session terminates the user's whole process tree, not just the
// immediate child. The in-process harness has no tailscaledPath, so
// this exercises the direct-exec (no incubator) path where the user
// shell spawns grandchildren: tailssh must signal the process group,
// which requires the direct-path cmd to be its own group leader.
func TestSessionTerminationKillsProcess(t *testing.T) {
	h := newTestSSHHarness(t)

	marker := fmt.Sprintf("tailssh-termination-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	// Two levels deep, on purpose. The outer sh is (or is exec'd over
	// by) cmd.Process, which exec.CommandContext kills on its own; the
	// inner sh is a grandchild that only dies if tailssh signals the
	// whole process group. The loop keeps the inner sh from exec'ing
	// over itself, so the marker stays in the survivor's argv.
	cmd := fmt.Sprintf(`/bin/sh -c '/bin/sh -c "while :; do sleep 1; done #%s" & wait'`, marker)

	t.Cleanup(func() {
		// Don't leave a 30s sleeper behind on failure.
		exec.Command("pkill", "-f", marker).Run()
	})

	cl, err := ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(cmd); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := tstest.WaitFor(10*time.Second, func() error {
		if !processWithMarkerRunning(t, marker) {
			return fmt.Errorf("marker process not started yet")
		}
		return nil
	}); err != nil {
		t.Fatalf("marker process never appeared: %v", err)
	}

	// Tear the whole connection down; the session context cancels and
	// tailssh must terminate the process tree.
	s.Close()
	cl.Close()

	if err := tstest.WaitFor(10*time.Second, func() error {
		if processWithMarkerRunning(t, marker) {
			return fmt.Errorf("process still running")
		}
		return nil
	}); err != nil {
		t.Fatalf("user process survived session teardown: %v", err)
	}
}
