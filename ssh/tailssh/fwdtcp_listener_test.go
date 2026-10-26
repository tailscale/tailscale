// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
)

// fwdCleanupContext reports when the listener removes its cancellation callback.
// fwdTestContext does not expose the underlying context's private values, so
// context.AfterFunc uses this method to register the callback.
type fwdCleanupContext struct {
	gliderssh.Context

	// stopped receives the result of each call to the stop function returned
	// by AfterFunc. The result is true if the callback was prevented from running.
	// The test must provide a non-nil channel with at least one buffer slot.
	stopped chan bool
}

func (c *fwdCleanupContext) AfterFunc(f func()) func() bool {
	stop := context.AfterFunc(c.Context, f)
	return func() bool {
		stopped := stop()
		c.stopped <- stopped
		return stopped
	}
}

func TestFwdTCPListenerCleanup(t *testing.T) {
	c := newFwdTestConn(t, fwdTestIdentity(t), &tailcfg.SSHAction{
		Accept:                    true,
		AllowRemotePortForwarding: true,
	})
	base, cancel := fwdTestCtx(fwdTestSSHConn{})
	defer cancel()
	ctx := &fwdCleanupContext{Context: base, stopped: make(chan bool, 1)}
	h := &fwdTCPHandler{conn: c}

	// Reuse one address on the same SSH connection. Canceling each forward
	// must release its listener and cancellation callback, not retain them
	// until the SSH connection closes.
	var port uint32
	for _, mode := range []string{"request", "request", "listener-close"} {
		req := &gossh.Request{
			Type:    "tcpip-forward",
			Payload: gossh.Marshal(fwdRemoteForwardRequest{BindAddr: "127.0.0.1", BindPort: port}),
		}
		ok, payload := h.HandleSSHRequest(ctx, nil, req)
		if !ok {
			t.Fatalf("tcpip-forward: %s", payload)
		}
		var reply fwdRemoteForwardSuccess
		if err := gossh.Unmarshal(payload, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.BindPort == 0 || port != 0 && reply.BindPort != port {
			t.Fatalf("bound port = %d, want nonzero and unchanged from %d", reply.BindPort, port)
		}
		port = reply.BindPort
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		h.mu.Lock()
		ln := h.forwards[addr]
		h.mu.Unlock()
		if ln == nil {
			t.Fatal("listener was not registered")
		}
		switch mode {
		case "request":
			ok, _ := h.HandleSSHRequest(ctx, nil, &gossh.Request{
				Type:    "cancel-tcpip-forward",
				Payload: gossh.Marshal(fwdRemoteForwardCancelRequest{BindAddr: "127.0.0.1", BindPort: port}),
			})
			if !ok {
				t.Fatal("cancel-tcpip-forward failed")
			}
		case "listener-close":
			ln.Close()
		}
		select {
		case stopped := <-ctx.stopped:
			if !stopped {
				t.Errorf("%s: cancellation callback was not stopped", mode)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: listener did not release its cancellation callback", mode)
		}
		h.mu.Lock()
		remaining := len(h.forwards)
		h.mu.Unlock()
		if remaining != 0 {
			t.Fatalf("%s: %d listeners remain", mode, remaining)
		}
		if ctx.Err() != nil {
			t.Fatal("canceling a forward closed the SSH connection context")
		}
	}
}
