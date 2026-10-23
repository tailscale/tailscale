// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// agentFwdConn is a gossh.Conn stub: ForwardAgentConnections only type
// asserts the context value to gossh.Conn, and OpenChannel is only reached
// if a connection arrives on the forwarded socket, which these tests never
// trigger.
type agentFwdConn struct{ gossh.Conn }

func (agentFwdConn) OpenChannel(string, []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	return nil, nil, errors.New("no channel")
}

// agentFwdContext implements gliderssh.Context: Value makes AgentRequested
// report true and ContextKeyConn return a usable conn stub; everything else
// is inert.
type agentFwdContext struct {
	context.Context
	*sync.Mutex
}

func (agentFwdContext) Value(key any) any {
	if key == gliderssh.ContextKeyConn {
		return agentFwdConn{}
	}
	return true
}
func (agentFwdContext) User() string                        { return "alice" }
func (agentFwdContext) SessionID() string                   { return "test" }
func (agentFwdContext) ClientVersion() string               { return "2.0" }
func (agentFwdContext) ServerVersion() string               { return "2.0" }
func (agentFwdContext) RemoteAddr() net.Addr                { return nil }
func (agentFwdContext) LocalAddr() net.Addr                 { return nil }
func (agentFwdContext) Permissions() *gliderssh.Permissions { return nil }
func (agentFwdContext) SetValue(key, value any)             {}

// agentFwdSession is a minimal gliderssh.Session for handleSSHAgentForwarding.
type agentFwdSession struct {
	gliderssh.Session
	ctx gliderssh.Context
}

func (s agentFwdSession) Context() gliderssh.Context { return s.ctx }

func newAgentTestSession() (*sshSession, *agentFwdSession) {
	c := &conn{
		srv:         &server{logf: logger.Discard},
		finalAction: &tailcfg.SSHAction{Accept: true, AllowAgentForwarding: true},
	}
	ctx := agentFwdContext{Context: context.Background(), Mutex: &sync.Mutex{}}
	ss := &sshSession{
		conn:    c,
		logf:    logger.Discard,
		Session: agentFwdSession{ctx: ctx}, // minimal Session; only Context() is used
	}
	return ss, &agentFwdSession{ctx: ctx}
}

// TestAgentForwardDirCleanup verifies that the agent forwarding socket's
// temp directory is removed when the session ends.
func TestAgentForwardDirCleanup(t *testing.T) {
	ln, err := gliderssh.NewAgentListener()
	if err != nil {
		t.Fatal(err)
	}
	ss, _ := newAgentTestSession()
	ss.agentListener = ln

	dir := filepath.Dir(ln.Addr().String())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("stat agent dir: %v", err)
	}
	ss.closeAgentForwarding()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("agent dir %q still exists after closeAgentForwarding (err=%v)", dir, err)
	}
	// Closing again must be a no-op (run's defer plus any other cleanup).
	ss.closeAgentForwarding()
}

// TestHandleSSHAgentForwardingDirHygiene verifies the socket and its
// containing directory are accessible only by the local user (0600 socket,
// 0700 user-owned directory), not group/world-accessible root-owned state.
func TestHandleSSHAgentForwardingDirHygiene(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skipf("skipping when not running as root: os.Chown is required")
	}

	const uid, gid = 1234, 1235
	ss, s := newAgentTestSession()
	lu := &userMeta{User: user.User{Username: "alice", Uid: fmt.Sprint(uid), Gid: fmt.Sprint(gid)}}

	if err := ss.handleSSHAgentForwarding(s, lu); err != nil {
		t.Fatalf("handleSSHAgentForwarding: %v", err)
	}
	t.Cleanup(ss.closeAgentForwarding)

	socketPath := ss.agentListener.Addr().String()
	dir := filepath.Dir(socketPath)

	si, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := si.Mode().Perm(); got != 0600 {
		t.Errorf("socket mode = %o; want 0600", got)
	}
	if int(si.Sys().(*syscall.Stat_t).Uid) != uid {
		t.Errorf("socket uid = %d; want %d", si.Sys().(*syscall.Stat_t).Uid, uid)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0700 {
		t.Errorf("dir mode = %o; want 0700", got)
	}
	if int(di.Sys().(*syscall.Stat_t).Uid) != uid {
		t.Errorf("dir uid = %d; want %d (must be owned by the session user, not root)", di.Sys().(*syscall.Stat_t).Uid, uid)
	}
}
