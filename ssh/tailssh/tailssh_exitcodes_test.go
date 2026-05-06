// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"os/user"
	"testing"

	gliderssh "github.com/tailscale/gliderssh"
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
	execSSH func(args ...string) *exec.Cmd
}

func newTestSSHHarness(t *testing.T) *testSSHHarness {
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

	return &testSSHHarness{user: u, execSSH: execSSH}
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
