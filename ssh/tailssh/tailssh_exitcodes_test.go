// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"os/user"
	"strings"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/crypto/ssh"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
)

// testSSHHarness is the in-process SSH server harness shared by TestSSH
// and TestExitCodePassthrough: a tailssh.server on a local listener
// with auth bypassed, plus an execSSH closure that talks to it via
// the system ssh client.
type testSSHHarness struct {
	user    *user.User
	addr    string // host:port of the local listener
	execSSH func(args ...string) *exec.Cmd
}

func newTestSSHHarness(t *testing.T) *testSSHHarness {
	t.Helper()
	return newTestSSHHarnessWithShell(t, "")
}

// newTestSSHHarnessWithShell is newTestSSHHarness with the session
// user's login shell pinned to shell (empty = the real login shell).
// Tests that depend on exact process/fd structure use /bin/sh: some
// real login shells (fish) fork -c commands and stay resident, which
// hides pipe EOFs and changes who the direct child is.
func newTestSSHHarnessWithShell(t *testing.T, shell string) *testSSHHarness {
	t.Helper()
	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystem()
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(eng)
	sys.Set(new(mem.Store))
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lb.Shutdown() })
	lb.SetVarRoot(t.TempDir())

	srv := &server{lb: lb, logf: logf}
	sc, err := srv.newConn()
	if err != nil {
		t.Fatal(err)
	}
	sc.insecureSkipTailscaleAuth = true

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	um, err := userLookup(u.Username)
	if err != nil {
		t.Fatal(err)
	}
	if shell != "" {
		um.loginShellCached = shell
	}
	sc.localUser = um
	sc.info = &sshConnInfo{
		sshUser: "test",
		src:     netip.MustParseAddrPort("1.2.3.4:32342"),
		dst:     netip.MustParseAddrPort("1.2.3.5:22"),
		node:    (&tailcfg.Node{}).View(),
		uprof:   tailcfg.UserProfile{},
	}
	sc.action0 = &tailcfg.SSHAction{Accept: true}
	sc.finalAction = sc.action0
	sc.authCompleted.Store(true)
	sc.Handler = func(s gliderssh.Session) {
		sc.newSSHSession(s).run()
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("Accept: %v", err)
				}
				return
			}
			go sc.HandleConn(c)
		}
	}()

	execSSH := func(args ...string) *exec.Cmd {
		cmd := exec.Command("ssh",
			"-F", "none",
			"-v",
			"-p", fmt.Sprint(port),
			"-o", "StrictHostKeyChecking=no",
			"user@127.0.0.1")
		cmd.Args = append(cmd.Args, args...)
		return cmd
	}

	return &testSSHHarness{user: u, addr: ln.Addr().String(), execSSH: execSSH}
}

// gatedWriter blocks its first Write until gate is closed, then
// writes everything to buf. Plugged in as the SSH client's stderr
// sink it stops the client from consuming extended data, which stops
// window adjustments, which exhausts the server's 2 MiB send window:
// real-network backpressure, produced deterministically.
type gatedWriter struct {
	gate <-chan struct{}
	buf  bytes.Buffer
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	<-w.gate
	return w.buf.Write(p)
}

// TestStderrTailNotTruncated asserts the full stderr stream reaches
// the client when the process exits while stderr is still in flight.
// The client withholds window credit (gatedWriter) so the server's
// stderr copier is stuck mid-backlog when the process exits and the
// stdout pipe EOFs. A CHANNEL_EOF sent at stdout-EOF, while stderr is
// still draining, makes every later stderr write fail and silently
// drops the tail; CHANNEL_EOF must wait for both streams.
func TestStderrTailNotTruncated(t *testing.T) {
	h := newTestSSHHarnessWithShell(t, "/bin/sh")

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
	defer s.Close()

	gate := make(chan struct{})
	stderr := &gatedWriter{gate: gate}
	var stdout bytes.Buffer
	s.Stdout = &stdout
	s.Stderr = stderr

	// 33 * 64 KiB = the client's 2 MiB channel window plus one pipe
	// buffer: enough that the window runs dry and the final stderr
	// chunks (and TAIL) are still server-side when the shell exits,
	// yet little enough that the shell doesn't block before exiting.
	const cmd = `dd if=/dev/zero bs=65536 count=33 1>&2 2>/dev/null; echo TAIL >&2; exit 7`

	// Release the client's stderr sink only after the exit (and, with
	// the bug, the premature CHANNEL_EOF) has happened server-side.
	timer := time.AfterFunc(750*time.Millisecond, func() { close(gate) })
	defer timer.Stop()

	err = s.Run(cmd)
	var ee *ssh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want *ssh.ExitError, got %T: %v", err, err)
	}
	if got := ee.ExitStatus(); got != 7 {
		t.Errorf("exit status = %d, want 7", got)
	}
	if got := stderr.buf.String(); !strings.Contains(got, "TAIL") {
		t.Errorf("stderr tail dropped: got %d of %d bytes, missing final TAIL marker", len(got), 33*65536+len("TAIL\n"))
	}
}

// TestExitCodePassthrough is the in-process, fast-feedback companion
// to TestIntegrationExitCodes: 0 / 42 / 127 via the system ssh client
// to an in-process tailssh.server. 127 = POSIX command-not-found.
// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08_02
func TestExitCodePassthrough(t *testing.T) {
	h := newTestSSHHarness(t)

	tests := []struct {
		name string
		cmd  string
		want int
	}{
		{"zero", "true", 0},
		{"passthrough", "exit 42", 42},
		{"command_not_found", "/nonexistent/binary", 127},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.execSSH(tt.cmd).Run()
			if tt.want == 0 {
				if err != nil {
					t.Fatalf("want exit 0, got error: %v", err)
				}
				return
			}
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("want *exec.ExitError, got %T: %v", err, err)
			}
			if got := ee.ExitCode(); got != tt.want {
				t.Errorf("exit code = %d, want %d", got, tt.want)
			}
		})
	}
}
