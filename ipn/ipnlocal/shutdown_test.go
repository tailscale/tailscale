// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"tailscale.com/ipn"
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
