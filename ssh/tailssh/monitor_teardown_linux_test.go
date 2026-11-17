// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/tstest"
)

// TestMonitorTeardownPinsLeadersUntilSIGKILL checks that RPC loss keeps
// exited leaders unreaped until group SIGKILL.
func TestMonitorTeardownPinsLeadersUntilSIGKILL(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	immune, err := mc.Exec(mustCtx(t), []string{"/bin/sh", "-c", "trap '' HUP; echo ready; exec sleep 300"}, nil, "/", false, nil, null, w, null)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(-immune.PID, unix.SIGKILL) })
	w.Close()
	r.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(r).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("ready = %q, %v", line, err)
	}
	leader, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "300"}, nil, "/", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(-leader.PID, unix.SIGKILL) })
	// Trigger teardown without a termination request.
	if err := mc.c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	checkPinned := func() error {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", leader.PID))
		if err != nil {
			return fmt.Errorf("leader was reaped before SIGKILL: %w", err)
		}
		fields := strings.Fields(string(b)[strings.LastIndexByte(string(b), ')')+1:])
		if len(fields) < 2 || fields[0] != "Z" || fields[1] != strconv.Itoa(mc.Pid()) {
			return fmt.Errorf("leader is not yet a zombie pinned by the monitor: %s", b)
		}
		return nil
	}
	if err := tstest.WaitFor(monTeardownReap/4, checkPinned); err != nil {
		t.Fatal(err)
	}
	// Check leader retention after half the grace period.
	time.Sleep(monTeardownReap / 2)
	if err := checkPinned(); err != nil {
		t.Fatal(err)
	}
	if pidGone(immune.PID) {
		t.Fatal("HUP-immune sibling exited before escalation")
	}
	if err := mc.Close(); err != nil {
		t.Fatal(err)
	}
	for _, child := range []monitorProcess{leader, immune} {
		if !pidGone(child.PID) {
			t.Errorf("child %d survived teardown", child.PID)
		}
	}
}
