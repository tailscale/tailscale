// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
)

// setShutdownKnob overrides one of the teardown duration knobs for the
// duration of the test, restoring its previous value (and so its previous
// default) afterwards.
func setShutdownKnob(t *testing.T, knob func() time.Duration, envVar string, val time.Duration) {
	t.Helper()
	old := knob()
	envknob.Setenv(envVar, val.String())
	t.Cleanup(func() {
		if old > 0 {
			envknob.Setenv(envVar, old.String())
		} else {
			// Restore the default rather than the zero value.
			envknob.Setenv(envVar, "")
		}
	})
}

// TestShutdownWithLingeringDescendant reproduces the shutdown hang: a session
// process exits, but a descendant that started its own session survives the
// session teardown and holds the process's stdio open, so the session's I/O
// copiers never see EOF. Before the teardown waits were bounded, the copiers
// (and with them server.Shutdown, and with that the whole daemon) blocked
// forever on that EOF, until systemd's stop timeout SIGKILLed tailscaled.
func TestShutdownWithLingeringDescendant(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %q; the lingering descendant needs setsid", runtime.GOOS)
	}
	setShutdownKnob(t, sshIODrainTimeout, "TS_SSH_IO_DRAIN_TIMEOUT", time.Second)
	setShutdownKnob(t, sshShutdownTimeout, "TS_SSH_SHUTDOWN_TIMEOUT", 5*time.Second)
	setShutdownKnob(t, sshHupEscalation, "TS_SSH_HUP_ESCALATION", 500*time.Millisecond)

	acceptRule := newSSHRule(&tailcfg.SSHAction{
		Accept:  true,
		Message: "Welcome to Tailscale SSH!",
	})
	s := &server{
		lb:   &localState{sshEnabled: true, matchingRule: acceptRule},
		logf: tstest.WhileTestRunningLogger(t),
	}
	src := netip.MustParseAddrPort("100.100.100.101:2231")
	dst := netip.MustParseAddrPort("100.100.100.102:22")
	sc, dc := memnet.NewTCPConn(src, dst, 1024)

	var clientLog bytes.Buffer // written by the client goroutine, logged once it is done
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		cfg := &testssh.ClientConfig{
			User:            "alice",
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
		// The session process (a shell) exits immediately, but the
		// background setsid'd descendant keeps running in its own session,
		// holding the session's stdio descriptors open.
		out, err := sess.CombinedOutput("setsid sleep 60 & exit 0")
		fmt.Fprintf(&clientLog, "client output %q, err %v\n", out, err)
	}()

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- s.HandleSSHConn(dc)
	}()

	// Wait for the lingering descendant to exist: the session has started
	// and its process has exited; its I/O is now wedged on the descendant.
	waitFor := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitFor) {
		if err := exec.Command("pgrep", "-f", "sleep 60").Run(); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Best effort cleanup of the deliberately lingering descendant.
	defer exec.Command("pkill", "-f", "sleep 60").Run()

	// Shutdown while the session is wedged: it must return within the
	// grace, not block until the daemon is SIGKILLed.
	const maxShutdown = 4 * time.Second
	t0 := time.Now()
	s.Shutdown()
	if d := time.Since(t0); d > maxShutdown {
		t.Errorf("Shutdown took %v with a wedged session; want within %v", d, maxShutdown)
	}

	select {
	case <-clientDone:
	case <-time.After(maxShutdown):
		t.Error("client did not finish after Shutdown")
	}
	t.Logf("%s", clientLog.String())
	if err := <-srvDone; err != nil {
		t.Errorf("HandleSSHConn: %v", err)
	}
}

// TestShutdownAbandonsStuckSession checks the Shutdown bound on its own: a
// session that never finishes must not keep Shutdown (and so a daemon stop)
// from returning.
func TestShutdownAbandonsStuckSession(t *testing.T) {
	setShutdownKnob(t, sshShutdownTimeout, "TS_SSH_SHUTDOWN_TIMEOUT", 500*time.Millisecond)

	s := &server{logf: tstest.WhileTestRunningLogger(t)}
	c := &conn{srv: s}
	ss := &sshSession{conn: c, sharedID: "sess-stuck"}
	if !s.attachSessionToConnIfNotShutdown(ss) {
		t.Fatal("session was not attached")
	}
	// The stuck session never detaches; nothing ever calls Done on its
	// behalf, which is the point.

	const maxShutdown = 3 * time.Second
	t0 := time.Now()
	s.Shutdown()
	if d := time.Since(t0); d > maxShutdown {
		t.Errorf("Shutdown took %v with a stuck session; want within %v", d, maxShutdown)
	}

	// A second Shutdown after the abandonment is a no-op.
	s.Shutdown()
}
