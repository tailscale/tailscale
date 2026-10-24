// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMonitorWatchdogHelperProcess is re-exec'd as a monitor-owned session
// or one-shot forwarding child. Both ignore parent-death SIGHUP so only
// orderly monitor teardown (including its SIGKILL pass) can stop them.
func TestMonitorWatchdogHelperProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--" || i+2 >= len(os.Args) || os.Args[i+1] != "watchdog-helper" {
			continue
		}
		signal.Ignore(syscall.SIGHUP)
		if err := os.WriteFile(os.Args[i+2], []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(3)
		}
		time.Sleep(25 * time.Second)
		os.Exit(0)
	}
}

// TestMonitorCloseWatchdogForwardChild reproduces the case where a stalled
// forwarding op consumes the watchdog before the monitor can tear down its
// HUP-immune session and forwarding child groups.
func TestMonitorCloseWatchdogForwardChild(t *testing.T) {
	markerDir := t.TempDir()
	forwardMarker := filepath.Join(markerDir, "forward-pid")
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join([]string{
		"-test.run=^TestMonitorWatchdogHelperProcess$", "-test.timeout=0", "--", "watchdog-helper", forwardMarker,
	}, " "))
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))

	// The session must be running and ignoring HUP before Close starts.
	sessionMarker := filepath.Join(markerDir, "session-pid")
	ctx, cancel := testCtx()
	session, err := mc.Exec(ctx, []string{monitorExe(t), "-test.run=^TestMonitorWatchdogHelperProcess$", "-test.timeout=0", "--", "watchdog-helper", sessionMarker}, nil, "/", false, nil)
	cancel()
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	defer func() {
		// Only signal this test's own session group, never a reused PID.
		if b, err := os.ReadFile(sessionMarker); err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(session.PID) && !processDead(session.PID) {
			_ = syscall.Kill(-session.PID, syscall.SIGKILL)
		}
	}()
	waitWatchdogMarker(t, sessionMarker, session.PID)

	requestDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		defer cancel()
		_, err := mc.Listen(ctx, "tcp", "127.0.0.1:0", false)
		requestDone <- err
	}()
	forwardPID := waitWatchdogMarker(t, forwardMarker, 0)
	defer func() {
		if !processDead(forwardPID) {
			_ = syscall.Kill(forwardPID, syscall.SIGKILL)
		}
	}()

	start := time.Now()
	err = mc.Close()
	t.Logf("Close duration=%v error=%v; session=%d forward=%d", time.Since(start), err, session.PID, forwardPID)
	if err != nil {
		t.Errorf("monitor failed to complete teardown: %v", err)
	}
	select {
	case err := <-requestDone:
		t.Logf("inflight Listen returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Error("inflight Listen did not return after Close")
	}
	if !processDead(forwardPID) {
		t.Errorf("HUP-immune forwarding child %d survived Close", forwardPID)
	}
	if !processDead(session.PID) {
		t.Errorf("HUP-immune session child %d survived Close", session.PID)
	}
}

func waitWatchdogMarker(t *testing.T, path string, wantPID int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil || pid <= 0 || (wantPID > 0 && pid != wantPID) {
				t.Fatalf("invalid helper PID marker %q: %q", path, b)
			}
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("helper did not write PID marker %q", path)
	return 0
}
