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
	"tailscale.com/tstest"
)

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
