// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest"
)

// TestNCHalfClose verifies that "tailscale nc" keeps sending stdin to a
// server that has closed its write side of the connection
// (tailscale/tailscale#22637), and that nc's own stdin EOF reaches the
// server as a half-close.
func TestNCHalfClose(t *testing.T) {
	tstest.Parallel(t)
	env := NewTestEnv(t)

	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	// In userspace networking mode, n2's netstack forwards connections to
	// its Tailscale IP to localhost.
	n2 := NewTestNode(t, env, TUNMode(false))
	d2 := n2.StartDaemon()

	n1.AwaitListening()
	n2.AwaitListening()
	n1.MustUp()
	n2.MustUp()
	n1.AwaitRunning()
	n2.AwaitRunning()
	if err := tstest.WaitFor(10*time.Second, func() error {
		if len(n1.MustStatus().Peer) == 0 {
			return errors.New("no peers")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	n2IP := n2.AwaitIP4()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// The server says hello, half-closes, then reads until the client's
	// half-close.
	gotCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			errCh <- err
			return
		}
		b, err := io.ReadAll(conn)
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- string(b)
	}()

	cmd := n1.TailscaleForOutput("nc", n2IP.String(), fmt.Sprint(port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// nc's stdout ends at the server's half-close...
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Fatalf("nc output = %q, want %q", out, "hello")
	}
	// ... but nc must still be running and sending stdin.
	if _, err := io.WriteString(stdin, "after server FIN"); err != nil {
		t.Fatalf("writing to nc's stdin after the server's FIN: %v", err)
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("tailscale nc: %v", err)
	}

	select {
	case got := <-gotCh:
		if got != "after server FIN" {
			t.Errorf("server got %q, want %q", got, "after server FIN")
		}
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for the server")
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}
