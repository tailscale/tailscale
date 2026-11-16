// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

type shutdownTestSSHServer struct {
	b     *LocalBackend
	calls atomic.Int32
	t     *testing.T
}

func (s *shutdownTestSSHServer) HandleSSHConn(net.Conn) error { return nil }
func (s *shutdownTestSSHServer) NumActiveConns() int          { return 0 }
func (s *shutdownTestSSHServer) OnPolicyChange()              {}

func (s *shutdownTestSSHServer) Shutdown() {
	s.calls.Add(1)
	if !s.b.mu.TryLock() {
		s.t.Error("LocalBackend.mu held while shutting down SSH server")
		return
	}
	s.b.mu.Unlock()
	s.b.NodeKey() // do something that requires the lock
}

func TestShutdownReleasesMutexBeforeWaitingForSubsystems(t *testing.T) {
	b := newTestLocalBackend(t)
	ssh := &shutdownTestSSHServer{b: b, t: t}
	b.mu.Lock()
	b.sshServer = ssh
	b.mu.Unlock()

	var certShutdownCalls atomic.Int32
	restore := HookShutdownCertRefreshLoop.SetForTest(func(b *LocalBackend) {
		certShutdownCalls.Add(1)
		if !b.mu.TryLock() {
			t.Error("LocalBackend.mu held while shutting down cert refresh loop")
			return
		}
		b.mu.Unlock()
		b.ServeConfig()
	})
	t.Cleanup(restore)

	b.Shutdown()
	b.Shutdown()

	if got := certShutdownCalls.Load(); got != 1 {
		t.Errorf("cert refresh shutdown called %d times; want 1", got)
	}
	if got := ssh.calls.Load(); got != 1 {
		t.Errorf("SSH shutdown called %d times; want 1", got)
	}
	if _, err := b.sshServerOrInit(); !errors.Is(err, errShutdown) {
		t.Errorf("sshServerOrInit after Shutdown = %v; want %v", err, errShutdown)
	}
}

func TestCertRefreshLoopDoesNotRestartAfterShutdown(t *testing.T) {
	b := newTestLocalBackend(t)
	var updates atomic.Int32
	restore := HookUpdateCertRefreshLoop.SetForTest(func(*LocalBackend, ipn.State, ipn.ServeConfigView) {
		updates.Add(1)
	})
	t.Cleanup(restore)

	b.Shutdown()
	b.mu.Lock()
	b.updateCertRefreshLoopLocked()
	b.mu.Unlock()

	if got := updates.Load(); got != 0 {
		t.Errorf("cert refresh loop restarted %d times after Shutdown; want 0", got)
	}
}

// closeCountingSSHConn records ownership cleanup without relying on a timeout
// to detect a connection left open by handleSSHConn.
type closeCountingSSHConn struct {
	net.Conn
	closes int
}

func (c *closeCountingSSHConn) Close() error {
	c.closes++
	return c.Conn.Close()
}

func TestHandleSSHConnAfterShutdownClosesConn(t *testing.T) {
	b := newTestLocalBackend(t)
	b.Shutdown()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &closeCountingSSHConn{Conn: server}
	if err := b.handleSSHConn(c); !errors.Is(err, errShutdown) {
		t.Fatalf("handleSSHConn after Shutdown = %v; want %v", err, errShutdown)
	}
	if c.closes != 1 {
		t.Fatalf("connection Close calls = %d; want 1", c.closes)
	}
	// Check the observable peer result, not just the call to Close.
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("peer Read after rejection = %v; want EOF", err)
	}
}

type handleSSHConnTestServer struct {
	shutdownTestSSHServer
	handle   func(net.Conn) error
	shutdown func()
}

func (s *handleSSHConnTestServer) HandleSSHConn(c net.Conn) error { return s.handle(c) }

func (s *handleSSHConnTestServer) Shutdown() {
	if s.shutdown != nil {
		s.shutdown()
		return
	}
	s.shutdownTestSSHServer.Shutdown()
}

func TestHandleSSHConnDelegatesConnectionOwnership(t *testing.T) {
	b := newTestLocalBackend(t)
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &closeCountingSSHConn{Conn: server}
	wantErr := errors.New("SSH server error")
	called := false
	b.sshServer = &handleSSHConnTestServer{
		shutdownTestSSHServer: shutdownTestSSHServer{b: b, t: t},
		handle: func(got net.Conn) error {
			called = true
			if got != c {
				t.Error("SSH server received different connection")
			}
			if c.closes != 0 {
				t.Errorf("connection closed before SSH handler: %d", c.closes)
			}
			got.Close()
			return wantErr
		},
	}
	if err := b.handleSSHConn(c); !errors.Is(err, wantErr) {
		t.Errorf("handleSSHConn = %v; want %v", err, wantErr)
	}
	if !called {
		t.Error("SSH server not called")
	}
	if c.closes != 1 {
		t.Errorf("connection Close calls = %d; want 1", c.closes)
	}
}

func TestTCPHandlerForDstRejectsSSHDuringShutdown(t *testing.T) {
	b := newTestLocalBackend(t)
	b.currentNode().SetNetMap(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}).View(),
	})
	b.sshAtomicBool.Store(true)
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &closeCountingSSHConn{Conn: server}
	called := false
	b.sshServer = &handleSSHConnTestServer{shutdown: func() {
		// Exercise routing after shutdownCalled is set but before engine teardown.
		called = true
		handler, _ := b.TCPHandlerForDst(netip.MustParseAddrPort("100.64.0.2:12345"), netip.MustParseAddrPort("100.64.0.1:22"))
		if handler == nil {
			t.Fatal("no SSH handler during shutdown")
		}
		if err := handler(c); !errors.Is(err, errShutdown) {
			t.Errorf("handler = %v; want %v", err, errShutdown)
		}
		if c.closes != 1 {
			t.Errorf("connection Close calls = %d; want 1", c.closes)
		}
	}}
	b.Shutdown()
	if !called {
		t.Fatal("SSH shutdown hook not called")
	}
}
