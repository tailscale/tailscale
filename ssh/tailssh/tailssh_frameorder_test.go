// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"net"
	"net/netip"
	"os/user"
	"slices"
	"sync"
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

// frameRecorder wraps a gliderssh.Session and records the order in
// which the server emits the three session-teardown frames. Frame
// order is a property of our own output, so it is observable on any
// GOOS without depending on how a particular client reacts to it.
type frameRecorder struct {
	gliderssh.Session
	mu     sync.Mutex
	frames []string
}

func (r *frameRecorder) record(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, name)
}

func (r *frameRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.frames)
}

func (r *frameRecorder) Exit(code int) error {
	r.record("exit-status")
	return r.Session.Exit(code)
}

func (r *frameRecorder) CloseWrite() error {
	r.record("eof")
	return r.Session.CloseWrite()
}

func (r *frameRecorder) Close() error {
	r.record("close")
	return r.Session.Close()
}

// TestExitStatusPrecedesEOF pins the session teardown frame order:
// exit-status, then CHANNEL_EOF, then CHANNEL_CLOSE (RFC 4254 §6.10).
//
// This is the bug behind #18256. Sending EOF first lets a client that
// treats EOF as end-of-session stop reading before the exit-status
// request arrives, and report a bogus 0. macOS OpenSSH does exactly
// that; Linux OpenSSH happens to read the pending request anyway, so
// an exit-code assertion can't see the defect and this ordering
// assertion is what pins it on every platform.
func TestExitStatusPrecedesEOF(t *testing.T) {
	recCh := make(chan *frameRecorder, 1)
	addr := newFrameOrderServer(t, recCh)

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
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
	// Produce output on both streams so neither copier is trivially
	// done before the process exits.
	if err := s.Run("echo out; echo err 1>&2; exit 7"); err == nil {
		t.Fatal("want non-nil error for exit 7")
	} else if ee, ok := err.(*ssh.ExitError); !ok {
		t.Fatalf("want *ssh.ExitError, got %T: %v", err, err)
	} else if ee.ExitStatus() != 7 {
		t.Fatalf("exit status = %d, want 7", ee.ExitStatus())
	}

	var rec *frameRecorder
	select {
	case rec = <-recCh:
	case <-time.After(10 * time.Second):
		t.Fatal("session never started")
	}

	// run() returns before the deferred ss.Close lands, so give the
	// close frame a moment rather than racing it.
	var got []string
	if err := tstest.WaitFor(5*time.Second, func() error {
		got = rec.got()
		if len(got) < 3 {
			return errNotAllFrames
		}
		return nil
	}); err != nil {
		t.Fatalf("only saw frames %v, want 3", got)
	}

	want := []string{"exit-status", "eof", "close"}
	if !slices.Equal(got, want) {
		t.Errorf("frame order = %v, want %v", got, want)
	}
}

var errNotAllFrames = errNotAllFramesType{}

type errNotAllFramesType struct{}

func (errNotAllFramesType) Error() string { return "not all frames emitted yet" }

// newFrameOrderServer is newTestSSHHarness with the session wrapped in
// a frameRecorder, which is delivered on recCh when the session starts.
func newFrameOrderServer(t *testing.T, recCh chan *frameRecorder) string {
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
	// /bin/sh: some login shells (fish) fork -c commands and stay
	// resident, which changes which process owns the pipes.
	um.loginShellCached = "/bin/sh"
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
		rec := &frameRecorder{Session: s}
		select {
		case recCh <- rec:
		default:
		}
		sc.newSSHSession(rec).run()
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go sc.HandleConn(c)
		}
	}()
	return ln.Addr().String()
}
