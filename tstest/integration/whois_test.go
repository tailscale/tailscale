// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest"
)

// TestUserspaceWhoIsProxyMap verifies that WhoIs lookups work via the
// proxymap in userspace-networking mode. It sets up two nodes (n1 and
// n2), starts a TCP listener on localhost, and has n1 connect to n2's
// Tailscale IP on the listener's port via "tailscale nc". Node n2's
// netstack forwards the connection to localhost, and the listener
// calls WhoIs on n2's LocalAPI to identify the remote peer as n1.
func TestUserspaceWhoIsProxyMap(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)

	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()

	n2 := NewTestNode(t, env)
	d2 := n2.StartDaemon()

	n1.AwaitListening()
	n2.AwaitListening()
	n1.MustUp()
	n2.MustUp()
	n1.AwaitRunning()
	n2.AwaitRunning()

	// Wait for n1 to see n2 as a peer.
	if err := tstest.WaitFor(10*time.Second, func() error {
		st := n1.MustStatus()
		if len(st.Peer) == 0 {
			return errors.New("no peers")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Verify the two nodes have different users. If they were the
	// same user, a WhoIs hit could pass trivially.
	st1 := n1.MustStatus()
	st2 := n2.MustStatus()
	if st1.Self.UserID == st2.Self.UserID {
		t.Fatalf("n1 and n2 have the same UserID %v; want different users", st1.Self.UserID)
	}
	t.Logf("n1: UserID=%v", st1.Self.UserID)
	t.Logf("n2: UserID=%v", st2.Self.UserID)

	n2IP := n2.AwaitIP4()
	t.Logf("n2 IP: %v", n2IP)

	// Start a TCP listener on localhost:0. When n1 connects to n2's
	// Tailscale IP on this port, n2's netstack (userspace networking)
	// will forward the connection to 127.0.0.1:<port>. The listener
	// uses n2's LocalAPI WhoIs to identify the connecting peer.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	t.Logf("listener on port %d", port)

	type result struct {
		msg string
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- result{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer conn.Close()

		// The RemoteAddr is 127.0.0.1:<ephemeral>, the local side of
		// n2's netstack dial. WhoIs on n2 should resolve this via the
		// proxymap to n1's Tailscale identity.
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		who, err := n2.LocalClient().WhoIs(ctx, conn.RemoteAddr().String())
		if err != nil {
			resultCh <- result{err: fmt.Errorf("WhoIs(%q): %w", conn.RemoteAddr(), err)}
			return
		}
		if who.Node == nil {
			resultCh <- result{err: errors.New("WhoIs returned nil Node")}
			return
		}
		if who.UserProfile == nil {
			resultCh <- result{err: errors.New("WhoIs returned nil UserProfile")}
			return
		}

		msg := fmt.Sprintf("Hello, %s (%v %v)!",
			who.UserProfile.LoginName, who.Node.Name, who.Node.ID)
		conn.Write([]byte(msg))
		resultCh <- result{msg: msg}
	}()

	// Use "tailscale nc" on n1 to connect to n2's Tailscale IP on
	// the listener port. This goes through n1's tailscaled, over
	// wireguard to n2's netstack, which dials localhost:<port>.
	//
	// We need to keep stdin open so nc doesn't exit before reading
	// the server's response (nc returns on the first goroutine to
	// complete: stdin→conn or conn→stdout).
	cmd := n1.TailscaleForOutput("nc", n2IP.String(), fmt.Sprint(port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.Output()
	stdin.Close()
	if err != nil {
		t.Fatalf("tailscale nc: %v", err)
	}

	// Verify the listener goroutine completed without error.
	r := <-resultCh
	if r.err != nil {
		t.Fatal(r.err)
	}

	got := string(out)
	if got != r.msg {
		t.Fatalf("nc output %q doesn't match server-sent message %q", got, r.msg)
	}
	const wantPrefix = "Hello, user-1@fake-control.example.net ("
	if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("got %q, want prefix %q", got, wantPrefix)
	}
	t.Logf("response: %s", got)

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}
