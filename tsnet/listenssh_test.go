// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tsnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	_ "tailscale.com/feature/ssh"
	"tailscale.com/ssh/tailssh"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// TestListenSSHAuthCallback tests Server.SSHAuthCallback end to end.
// A tsnet.Server whose callback denies the peer refuses the session
// and never yields it to Accept. A tsnet.Server whose callback allows
// the peer yields the session to Accept.
func TestListenSSHAuthCallback(t *testing.T) {
	ctx := t.Context()

	controlURL, _ := startControl(t)
	srvNode, srvIP, _ := startServer(t, ctx, controlURL, "sshauthsrv")
	clientNode, clientIP, _ := startServer(t, ctx, controlURL, "sshauthclient")

	if err := tstest.WaitFor(30*time.Second, func() error {
		lc, err := srvNode.LocalClient()
		if err != nil {
			return err
		}
		st, err := lc.Status(ctx)
		if err != nil {
			return err
		}
		for _, peer := range st.Peer {
			if slices.Contains(peer.TailscaleIPs, clientIP) {
				return nil
			}
		}
		return errors.New("clientNode not yet in srvNode's netmap")
	}); err != nil {
		t.Fatal(err)
	}

	// runAgainst dials srvNode's SSH listener from clientNode, runs a
	// command, and returns the exit error and output.
	runAgainst := func(ln net.Listener) (string, error) {
		t.Helper()
		addr := net.JoinHostPort(srvIP.String(), "22")
		if _, port, _ := net.SplitHostPort(ln.Addr().String()); port != "" && port != "0" {
			addr = net.JoinHostPort(srvIP.String(), port)
		}
		tcpConn, err := clientNode.Dial(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		t.Cleanup(func() { tcpConn.Close() })
		sshConn, chans, reqs, err := gossh.NewClientConn(tcpConn, addr, &gossh.ClientConfig{
			User:            "test",
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			return "", err
		}
		sshClient := gossh.NewClient(sshConn, chans, reqs)
		t.Cleanup(func() { sshClient.Close() })
		session, err := sshClient.NewSession()
		if err != nil {
			return "", err
		}
		t.Cleanup(func() { session.Close() })
		out, err := session.CombinedOutput("hello")
		return string(out), err
	}

	// A denying callback refuses the session at open.
	srvNode.SSHAuthCallback = func(peer tailcfg.NodeView, userProfile tailcfg.UserProfile) bool {
		t.Logf("auth callback invoked for peer %v (login %q)", peer.ID(), userProfile.LoginName)
		return false
	}
	denyLn, err := srvNode.ListenSSH(":2222")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { denyLn.Close() })

	out, err := runAgainst(denyLn)
	if err == nil {
		t.Fatalf("session was not refused by the deny callback; output %q", out)
	}
	var exitErr *gossh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
		t.Errorf("refusal error = %v; want exit status 1, got %v", err, exitErr)
	}
	select {
	case conn, ok := <-acceptCh(denyLn):
		if ok {
			t.Error("session was yielded to Accept despite denial")
			conn.Close()
		}
	case <-time.After(2 * time.Second):
		// No session was yielded, as expected.
	}

	// An allowing callback yields the session, and the application
	// can talk to it.
	srvNode.SSHAuthCallback = func(peer tailcfg.NodeView, userProfile tailcfg.UserProfile) bool {
		return true
	}
	allowLn, err := srvNode.ListenSSH(":2223")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { allowLn.Close() })

	go func() {
		conn, err := allowLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sess := conn.(*tailssh.Session)
		defer sess.Exit(0)
		fmt.Fprintf(sess, "allowed:%v\n", sess.UserProfile().LoginName != "")
	}()

	out, err = runAgainst(allowLn)
	if err != nil {
		t.Fatalf("session on allow listener failed: %v", err)
	}
	if got, want := strings.TrimSpace(string(out)), "allowed:true"; got != want {
		t.Errorf("client output = %q; want %q", got, want)
	}
}

func acceptCh(ln net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(ch)
			return
		}
		ch <- conn
	}()
	return ch
}

// TestListenSSH starts two tsnet nodes on a test tailnet, has one listen
// for SSH via ListenSSH, and has the other connect using the Go
// x/crypto/ssh client. The server verifies the command string and echoes
// back the connecting peer's login name, verifying that WhoIs and
// Peer/UserProfile work end-to-end.
func TestListenSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	srvNode, srvIP, _ := startServer(t, ctx, controlURL, "sshsrv")
	clientNode, clientIP, _ := startServer(t, ctx, controlURL, "sshclient")

	// Listen for SSH on srvNode.
	ln, err := srvNode.ListenSSH(":22")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	// Server goroutine: verify the command, then write the peer's login name back.
	srvErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		sess := conn.(*tailssh.Session)
		defer sess.Exit(0)
		if got := sess.RawCommand(); got != "test-whoami" {
			srvErrCh <- fmt.Errorf("server got command %q, want %q", got, "test-whoami")
			return
		}
		fmt.Fprintf(sess, "%s\n", sess.UserProfile().LoginName)
		srvErrCh <- nil
	}()

	// Wait until srvNode knows about clientNode so WhoIs succeeds when the
	// SSH connection arrives.
	if err := tstest.WaitFor(30*time.Second, func() error {
		lc, err := srvNode.LocalClient()
		if err != nil {
			return err
		}
		st, err := lc.Status(ctx)
		if err != nil {
			return err
		}
		for _, peer := range st.Peer {
			if slices.Contains(peer.TailscaleIPs, clientIP) {
				return nil
			}
		}
		return errors.New("clientNode not yet in srvNode's netmap")
	}); err != nil {
		t.Fatal(err)
	}

	// Dial srvNode's SSH listener from clientNode's Tailscale network.
	addr := net.JoinHostPort(srvIP.String(), "22")
	tcpConn, err := clientNode.Dial(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	// gliderssh defaults to NoClientAuth when no auth handler is registered,
	// so no Auth methods are needed.
	sshConn, chans, reqs, err := gossh.NewClientConn(tcpConn, addr, &gossh.ClientConfig{
		User:            "test",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sshClient := gossh.NewClient(sshConn, chans, reqs)
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.Output("test-whoami")
	if err != nil {
		t.Fatalf("session.Output: %v", err)
	}

	loginName := strings.TrimSpace(string(out))
	if loginName == "" {
		t.Error("SSH server returned empty login name; WhoIs or Peer/UserProfile may be broken")
	}
	t.Logf("peer login name from SSH server: %q", loginName)

	if err := <-srvErrCh; err != nil {
		t.Errorf("SSH server goroutine: %v", err)
	}
}
