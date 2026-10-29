// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
)

// setShutdownKnob sets a teardown timeout for the test and restores its
// previous positive value or the default during cleanup.
func setShutdownKnob(t *testing.T, knob func() time.Duration, envVar string, val time.Duration) {
	t.Helper()
	old := knob()
	envknob.Setenv(envVar, val.String())
	t.Cleanup(func() {
		if old > 0 {
			envknob.Setenv(envVar, old.String())
		} else {
			// Non-positive values select the default timeout.
			envknob.Setenv(envVar, "")
		}
	})
}

// TestShutdownWithLingeringDescendant runs an SSH command whose shell exits
// while a descendant in a separate session keeps stdout and stderr open.
// Shutdown must return after the I/O drain timeout, before the longer server
// shutdown timeout. A PID file confirms the descendant started and permits
// cleanup without terminating unrelated processes.
func TestShutdownWithLingeringDescendant(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %q; requires the setsid command-line utility", runtime.GOOS)
	}
	setShutdownKnob(t, sshIODrainTimeout, "TS_SSH_IO_DRAIN_TIMEOUT", time.Second)
	setShutdownKnob(t, sshShutdownTimeout, "TS_SSH_SHUTDOWN_TIMEOUT", 5*time.Second)
	setShutdownKnob(t, sshHupEscalation, "TS_SSH_HUP_ESCALATION", 500*time.Millisecond)

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	acceptRule := newSSHRule(&tailcfg.SSHAction{
		Accept:  true,
		Message: "Welcome to Tailscale SSH!",
	})
	// Permit the current user explicitly, including root in privileged tests.
	acceptRule.SSHUsers = map[string]string{u.Username: u.Username}
	s := &server{
		lb:   &localState{sshEnabled: true, matchingRule: acceptRule, varRoot: t.TempDir()},
		logf: tstest.WhileTestRunningLogger(t),
	}
	src := netip.MustParseAddrPort("100.100.100.101:2231")
	dst := netip.MustParseAddrPort("100.100.100.102:22")
	sc, dc := memnet.NewTCPConn(src, dst, 1024)

	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				if p, err := os.FindProcess(pid); err == nil {
					p.Kill()
				}
			}
		}
	})
	defer sc.Close()
	defer dc.Close()

	var clientLog bytes.Buffer // Written by the client goroutine.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		cfg := &testssh.ClientConfig{
			User:            u.Username,
			HostKeyCallback: testssh.InsecureIgnoreHostKey(),
		}
		c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			fmt.Fprintf(&clientLog, "client connect: %v\n", err)
			return
		}
		client := testssh.NewClient(c, chans, reqs)
		defer client.Close()
		sess, err := client.NewSession()
		if err != nil {
			fmt.Fprintf(&clientLog, "client session: %v\n", err)
			return
		}
		defer sess.Close()
		// The descendant starts a separate session and keeps stdio open
		// after the shell exits.
		out, err := sess.CombinedOutput(fmt.Sprintf("setsid sh -c 'echo $$ > %s; exec sleep 60' & exit 0", pidFile))
		fmt.Fprintf(&clientLog, "client output %q, err %v\n", out, err)
	}()

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- s.HandleSSHConn(dc)
	}()

	// Wait for the descendant to start.
	waitFor := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 {
			break
		}
		select {
		case <-clientDone:
			t.Fatalf("client finished before descendant started: %s; server error: %v", clientLog.String(), <-srvDone)
		default:
		}
		if time.Now().After(waitFor) {
			t.Fatal("descendant did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	const maxShutdown = 4 * time.Second
	t0 := time.Now()
	s.Shutdown()
	if d := time.Since(t0); d > maxShutdown {
		t.Errorf("Shutdown took %v with a wedged session; want within %v", d, maxShutdown)
	}

	select {
	case <-clientDone:
	case <-time.After(maxShutdown):
		t.Fatal("client did not finish after Shutdown")
	}
	t.Logf("%s", clientLog.String())
	if err := <-srvDone; err != nil {
		t.Errorf("HandleSSHConn: %v", err)
	}
}

// TestShutdownAbandonsStuckSession attaches a session that cannot finish until
// test cleanup detaches it. Shutdown must return within its time limit on both
// calls, even though the session WaitGroup remains nonzero.
func TestShutdownAbandonsStuckSession(t *testing.T) {
	setShutdownKnob(t, sshShutdownTimeout, "TS_SSH_SHUTDOWN_TIMEOUT", 500*time.Millisecond)

	s := &server{logf: tstest.WhileTestRunningLogger(t)}
	c := &conn{srv: s}
	ss := &sshSession{conn: c, sharedID: "sess-stuck"}
	if !s.attachSessionToConnIfNotShutdown(ss) {
		t.Fatal("session was not attached")
	}
	t.Cleanup(func() { c.detachSession(ss) })

	const maxShutdown = 3 * time.Second
	t0 := time.Now()
	s.Shutdown()
	if d := time.Since(t0); d > maxShutdown {
		t.Errorf("Shutdown took %v with a stuck session; want within %v", d, maxShutdown)
	}

	// Repeated Shutdown calls must also return.
	s.Shutdown()
}
