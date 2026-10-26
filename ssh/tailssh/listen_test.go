// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
)

var (
	testClientAddr = netip.MustParseAddrPort("100.100.100.101:2231")
	testServerAddr = netip.MustParseAddrPort("100.100.100.102:22")
	testPeerNode   = (&tailcfg.Node{
		ID:   1,
		User: 10,
		Name: "client.example.ts.net.",
	}).View()
	testPeerProfile = tailcfg.UserProfile{
		ID:        10,
		LoginName: "client@example.com",
	}
)

// startTestSSHListener starts a listenSSH server over memnet. The
// stub whoIs resolves every connection to testPeerNode. It returns
// the SSH listener and the raw listener to dial from the client side.
//
// It registers no cleanup. A test that runs inside a
// [synctest.Test] bubble must close the listener with a defer, because
// the bubble expects its goroutines to finish before the test returns.
// Other tests should use newTestSSHListener, which registers the
// cleanup.
func startTestSSHListener(t *testing.T, auth ipnlocal.SSHAuthCallback) (net.Listener, *memnet.Listener) {
	t.Helper()
	rawLn := memnet.Listen(testServerAddr.String())
	rawLn.NewConn = func(network, addr string, maxBuf int) (memnet.Conn, memnet.Conn) {
		return memnet.NewTCPConn(testClientAddr, testServerAddr, maxBuf)
	}
	sl, err := newSSHListener(rawLn, sshListenerConfig{
		varRoot: t.TempDir(),
		whoIs: func(proto string, ipp netip.AddrPort) (tailcfg.NodeView, tailcfg.UserProfile, bool) {
			return testPeerNode, testPeerProfile, true
		},
		auth: auth,
		logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sl, rawLn
}

// newTestSSHListener is startTestSSHListener with a cleanup that
// closes the listener. Do not use it inside a [synctest.Test] bubble.
func newTestSSHListener(t *testing.T, auth ipnlocal.SSHAuthCallback) (net.Listener, *memnet.Listener) {
	t.Helper()
	sl, rawLn := startTestSSHListener(t, auth)
	t.Cleanup(func() { sl.Close() })
	return sl, rawLn
}

// startTestSSHClient dials rawLn and completes the SSH handshake from
// the client side. It returns the raw connection and the SSH client.
// It registers no cleanup, for the same reason as
// startTestSSHListener. Use dialTestSSHListener outside a
// [synctest.Test] bubble.
func startTestSSHClient(t *testing.T, rawLn *memnet.Listener) (net.Conn, *testssh.Client) {
	t.Helper()
	sc, err := rawLn.Dial(t.Context(), "tcp", rawLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
		User:            "test",
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return sc, testssh.NewClient(c, chans, reqs)
}

// dialTestSSHListener is startTestSSHClient with cleanups that close
// the raw connection and the SSH client.
func dialTestSSHListener(t *testing.T, rawLn *memnet.Listener) *testssh.Client {
	t.Helper()
	sc, client := startTestSSHClient(t, rawLn)
	t.Cleanup(func() { sc.Close() })
	t.Cleanup(func() { client.Close() })
	return client
}

// TestListenSSHPTYRaw tests that a session from a PTY request does not
// translate "\n" to "\r\n". The translation is gliderssh PTY emulation,
// and it corrupts data written through the net.Conn interface.
func TestListenSSHPTYRaw(t *testing.T) {
	sl, rawLn := newTestSSHListener(t, nil)
	client := dialTestSSHListener(t, rawLn)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 80, 40, nil); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// Accept the session and write a line.
	conn, err := sl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	s := conn.(*Session)
	defer s.Close()
	if _, _, ok := s.Pty(); !ok {
		t.Fatal("session reports no PTY despite the pty-req")
	}
	if _, err := s.Write([]byte("a\n")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if err := s.Exit(0); err != nil {
		t.Fatalf("Exit: %v", err)
	}

	if err := sess.Wait(); err != nil {
		t.Fatalf("client wait: %v", err)
	}
	if got := out.String(); got != "a\n" {
		t.Errorf("client got %q; want %q (PTY emulation must be disabled for tsnet sessions)", got, "a\n")
	}
}

// TestListenSSHAuthCallback tests the authorization callback. A
// session the callback rejects is refused and never reaches Accept.
// A session the callback accepts is yielded to Accept. When no
// callback is set, every resolved peer is accepted.
func TestListenSSHAuthCallback(t *testing.T) {
	runCase := func(t *testing.T, auth ipnlocal.SSHAuthCallback, wantYield bool) *tailcfg.NodeView {
		t.Helper()
		var mu sync.Mutex
		var seen tailcfg.NodeView
		gotPeer := func() tailcfg.NodeView {
			mu.Lock()
			defer mu.Unlock()
			return seen
		}
		cb := auth
		if cb != nil {
			cb = func(n tailcfg.NodeView, p tailcfg.UserProfile) bool {
				mu.Lock()
				seen = n
				mu.Unlock()
				return auth(n, p)
			}
		}
		sl, rawLn := newTestSSHListener(t, cb)
		client := dialTestSSHListener(t, rawLn)

		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("NewSession: %v", err)
		}
		defer sess.Close()
		var out bytes.Buffer
		sess.Stdout = &out
		if err := sess.Start("hello"); err != nil {
			t.Fatalf("session start: %v", err)
		}

		accCh := make(chan *Session, 1)
		go func() {
			c, err := sl.Accept()
			if err == nil {
				accCh <- c.(*Session)
			}
		}()
		select {
		case s := <-accCh:
			if !wantYield {
				t.Errorf("session was yielded to Accept despite denial")
				s.Close()
			} else {
				// The callback saw the peer, and the session
				// exposes the same peer to the application.
				if got := s.Peer().Name(); got != testPeerNode.Name() {
					t.Errorf("Session.Peer().Name() = %q; want %q", got, testPeerNode.Name())
				}
				fmt.Fprintf(s, "hi\n")
				s.Exit(0)
			}
		case <-time.After(3 * time.Second):
			if wantYield {
				t.Error("session was not yielded to Accept")
			}
		}

		waitErr := make(chan error, 1)
		go func() { waitErr <- sess.Wait() }()
		select {
		case <-waitErr:
		case <-time.After(15 * time.Second):
			t.Error("session did not finish")
		}
		if wantYield && out.String() != "hi\n" {
			t.Errorf("client output = %q; want %q", out.String(), "hi\n")
		}
		return new(gotPeer())
	}

	t.Run("deny", func(t *testing.T) {
		seen := runCase(t, func(n tailcfg.NodeView, p tailcfg.UserProfile) bool {
			return false
		}, false)
		if seen == nil {
			t.Error("auth callback was not invoked")
		} else if seen.Name() != testPeerNode.Name() {
			t.Errorf("auth callback saw peer %q; want %q", seen.Name(), testPeerNode.Name())
		}
	})
	t.Run("allow", func(t *testing.T) {
		runCase(t, func(n tailcfg.NodeView, p tailcfg.UserProfile) bool {
			return true
		}, true)
	})
	t.Run("no-callback-accepts", func(t *testing.T) {
		runCase(t, nil, true)
	})
}

// TestListenSSHSessionQueueBound tests that when the application
// stops calling Accept, at most maxQueuedSSHListenerSessions sessions
// wait in the queue. Further sessions are refused.
func TestListenSSHSessionQueueBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sl, rawLn := startTestSSHListener(t, nil)
		defer sl.Close()
		sc, client := startTestSSHClient(t, rawLn)
		defer sc.Close()
		defer client.Close()
		_ = sl // intentionally never Accept'ed

		const total = maxQueuedSSHListenerSessions + 1
		waitErrs := make([]chan error, total)
		for i := range waitErrs {
			sess, err := client.NewSession()
			if err != nil {
				t.Fatalf("session %d: %v", i, err)
			}
			waitErrs[i] = make(chan error, 1)
			go func() {
				defer sess.Close()
				waitErrs[i] <- sess.Run("true")
			}()
		}

		// Exactly one session, the one past the queue bound, is refused
		// with exit status 1. The sessions in the queue stay parked and
		// report no exit status.
		deadline := time.Now().Add(15 * time.Second)
		refused := 0
		for refused == 0 && time.Now().Before(deadline) {
			for i := range waitErrs {
				select {
				case err := <-waitErrs[i]:
					if err == nil {
						t.Fatalf("session %d exited 0; want it parked or refused", i)
					}
					var exitErr *testssh.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
						t.Fatalf("session %d: %v; want exit status 1 (queue full)", i, err)
					}
					refused++
				default:
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if refused != 1 {
			t.Errorf("refused sessions = %d; want exactly 1 (queue of %d full)", refused, maxQueuedSSHListenerSessions)
		}

		// The queued sessions are still running.
		time.Sleep(500 * time.Millisecond)
		for i := range waitErrs {
			select {
			case err := <-waitErrs[i]:
				t.Errorf("queued session %d exited early: %v; want parked", i, err)
			default:
			}
		}
	})
}

// TestListenSSHIdleTimeout tests the TS_SSH_IDLE_TIMEOUT idle bound.
// Set to one second, a connection with no traffic is closed. Unset,
// and set to zero, the connection stays open. The test runs in a
// synctest bubble, so the sleeps use virtual time.
func TestListenSSHIdleTimeout(t *testing.T) {
	runCase := func(t *testing.T, val string) (alive bool) {
		t.Helper()
		if val != "" {
			envknob.SetenvForTest(t, "TS_SSH_IDLE_TIMEOUT", val)
		}
		synctest.Test(t, func(t *testing.T) {
			sl, rawLn := startTestSSHListener(t, nil)
			defer sl.Close()
			sc, client := startTestSSHClient(t, rawLn)
			defer sc.Close()
			defer client.Close()

			// Open a session channel, then stop sending traffic.
			sess, err := client.NewSession()
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			defer sess.Close()

			// Wait out the idle bound.
			time.Sleep(2 * time.Second)
			sess2, err := client.NewSession()
			if err != nil {
				alive = false // transport gone
				return
			}
			sess2.Close()
			alive = true
		})
		return alive
	}

	t.Run("on", func(t *testing.T) {
		if alive := runCase(t, "1"); alive {
			t.Error("silent connection survived the 1s idle timeout")
		}
	})
	t.Run("off-unset", func(t *testing.T) {
		if alive := runCase(t, ""); !alive {
			t.Error("connection closed despite no TS_SSH_IDLE_TIMEOUT (default off)")
		}
	})
	t.Run("off-zero", func(t *testing.T) {
		if alive := runCase(t, "0"); !alive {
			t.Error("connection closed despite TS_SSH_IDLE_TIMEOUT=0 (disabled)")
		}
	})
}

// TestSSHTimeoutKnobs tests the SSH timeout knob parsing. Both knobs
// accept a Go duration such as "90s" or a bare number of seconds such
// as "90". An invalid value uses the default.
func TestSSHTimeoutKnobs(t *testing.T) {
	if got := sshIdleTimeout(); got != 0 {
		t.Errorf("sshIdleTimeout (unset) = %v; want 0 (off by default)", got)
	}
	if got := loginGraceTime(); got != 120*time.Second {
		t.Errorf("loginGraceTime (unset) = %v; want 120s", got)
	}

	for _, tt := range []struct {
		val  string
		want time.Duration
	}{
		{"90s", 90 * time.Second},
		{"30", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"500ms", 500 * time.Millisecond},
		{"bogus", 0},
	} {
		envknob.SetenvForTest(t, "TS_SSH_IDLE_TIMEOUT", tt.val)
		want := tt.want
		if tt.val == "bogus" {
			want = 0
		}
		if got := sshIdleTimeout(); got != want {
			t.Errorf("sshIdleTimeout (%q) = %v; want %v", tt.val, got, want)
		}
	}
	for _, tt := range []struct {
		val  string
		want time.Duration
	}{
		{"90s", 90 * time.Second},
		{"120", 120 * time.Second},
		{"2m", 2 * time.Minute},
		{"0", 120 * time.Second},
		{"bogus", 120 * time.Second},
	} {
		envknob.SetenvForTest(t, "TS_SSH_LOGIN_GRACE_TIME", tt.val)
		if got := loginGraceTime(); got != tt.want {
			t.Errorf("loginGraceTime (%q) = %v; want %v", tt.val, got, tt.want)
		}
	}
}

// TestListenSSHWindowChangesWithoutPty tests that window changes are
// delivered when the application never calls Pty. gliderssh writes
// window changes from the session request loop, so without a drain the
// requests block, and the client waits for replies that never arrive.
func TestListenSSHWindowChangesWithoutPty(t *testing.T) {
	sl, rawLn := newTestSSHListener(t, nil)
	client := dialTestSSHListener(t, rawLn)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 80, 40, nil); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// The application accepts the session and never calls Pty.
	conn, err := sl.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	winErr := make(chan error, 1)
	go func() {
		for range 5 {
			if err := sess.WindowChange(100, 50); err != nil {
				winErr <- err
				return
			}
		}
		// A request that wants a reply must still be answered, which
		// proves the session request loop is not blocked.
		_, err := sess.SendRequest("break", true, nil)
		winErr <- err
	}()
	select {
	case err := <-winErr:
		if err != nil {
			t.Fatalf("WindowChange: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("window changes blocked; the session request loop is stuck")
	}
	conn.(*Session).Exit(0)
	if err := sess.Wait(); err != nil {
		t.Fatalf("client wait: %v", err)
	}
}

// TestListenSSHListenerCloseClosesSessions tests that closing the
// listener ends the sessions it accepted, so they do not outlive the
// listener.
func TestListenSSHListenerCloseClosesSessions(t *testing.T) {
	sl, rawLn := newTestSSHListener(t, nil)
	client := dialTestSSHListener(t, rawLn)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	// The session is parked in the queue, and the application never
	// accepts it.
	if err := sl.Close(); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- sess.Wait() }()
	select {
	case err := <-waitErr:
		if err == nil {
			t.Fatal("parked session exited 0; want the refused exit status 1")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parked session outlived the listener")
	}
}
