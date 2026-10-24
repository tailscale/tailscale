// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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

// newAgentTestSession returns a minimal sshSession (with its gliderssh
// Session stub) on the given conn, for driving handleSSHAgentForwarding.
// The conn comes from the test at hand: agent tests pass a monitor-backed
// conn (fwdmonitor_test.go's newFwdTestConn) so the listener is created by
// the bound-identity child.
func newAgentTestSession(t *testing.T, c *conn) (*sshSession, *agentFwdSession) {
	t.Helper()
	if c.srv == nil {
		c.srv = &server{logf: logger.Discard}
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
// temp directory is removed when the session ends, driving the real
// handleSSHAgentForwarding path (the socket and dir are created by the
// monitor's bound-identity child).
func TestAgentForwardDirCleanup(t *testing.T) {
	lu := fwdTestIdentity(t)
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true, AllowAgentForwarding: true})
	ss, s := newAgentTestSession(t, c)

	if err := ss.handleSSHAgentForwarding(s, lu); err != nil {
		t.Fatalf("handleSSHAgentForwarding: %v", err)
	}
	if ss.agentListener == nil {
		t.Fatal("agent listener not set")
	}
	dir := filepath.Dir(ss.agentListener.Addr().String())
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
// 0700 user-owned directory), created by a child with the session user's
// credentials, not group/world-accessible root-owned state. Root runs
// bind the monitor to the non-root test user. Non-root runs bind to the
// current user, where a non-root tailscaled forwards as itself.
func TestHandleSSHAgentForwardingDirHygiene(t *testing.T) {
	lu := fwdTestIdentity(t)
	uid, err := strconv.Atoi(lu.Uid)
	if err != nil {
		t.Fatal(err)
	}
	c := newFwdTestConn(t, lu, &tailcfg.SSHAction{Accept: true, AllowAgentForwarding: true})
	ss, s := newAgentTestSession(t, c)

	if err := ss.handleSSHAgentForwarding(s, lu); err != nil {
		t.Fatalf("handleSSHAgentForwarding: %v", err)
	}
	t.Cleanup(ss.closeAgentForwarding)

	// The session environment's SSH_AUTH_SOCK is the listener's address.
	socketPath := ss.agentListener.Addr().String()
	if !strings.HasPrefix(filepath.Dir(socketPath), "/tmp/auth-agent") {
		t.Errorf("agent socket path %q not in a /tmp/auth-agent* dir", socketPath)
	}

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

	di, err := os.Stat(filepath.Dir(socketPath))
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

// fakeFileInfo backs the checkAgentDirRemovable table: it lets the
// wrong-owner and not-a-directory cases run without a second uid.
type fakeFileInfo struct {
	name string
	mode os.FileMode
	sys  any
}

func (fi fakeFileInfo) Name() string       { return fi.name }
func (fi fakeFileInfo) Size() int64        { return 0 }
func (fi fakeFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fi fakeFileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi fakeFileInfo) Sys() any           { return fi.sys }

// TestCheckAgentDirRemovable pins the removal guard for the
// agent-forwarding directory. The path was reported by a child running
// as the connection's user, and the removal runs as root: only a real
// directory (Lstat, so a symlink does not pass), owned by the bound
// user and without group or other access, may be removed.
func TestCheckAgentDirRemovable(t *testing.T) {
	lu := &userMeta{User: user.User{Uid: "1000", Username: "u"}}
	// A real MkdirTemp directory: the shape the fwd child is supposed
	// to produce, owned by the current user.
	dir, err := os.MkdirTemp("", "auth-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	luSelf := &userMeta{User: user.User{Uid: strconv.Itoa(os.Getuid()), Username: "self"}}
	if err := checkAgentDirRemovable(fi, luSelf); err != nil {
		t.Fatalf("checkAgentDirRemovable(real MkdirTemp dir) = %v, want nil", err)
	}

	if err := checkAgentDirRemovable(fakeFileInfo{name: "auth-agent1", mode: 0o700 | os.ModeDir, sys: &syscall.Stat_t{Uid: 1000}}, lu); err != nil {
		t.Fatalf("checkAgentDirRemovable(bound-user dir) = %v, want nil", err)
	}

	for _, tt := range []struct {
		name string
		fi   os.FileInfo
		lu   *userMeta
	}{
		{"group-accessible dir", fakeFileInfo{name: "auth-agent1", mode: 0o750 | os.ModeDir, sys: &syscall.Stat_t{Uid: 1000}}, lu},
		{"world-accessible dir", fakeFileInfo{name: "auth-agent1", mode: 0o755 | os.ModeDir, sys: &syscall.Stat_t{Uid: 1000}}, lu},
		{"symlink to a directory", fakeFileInfo{name: "auth-agent1", mode: 0o777 | os.ModeSymlink, sys: &syscall.Stat_t{Uid: 1000}}, lu},
		{"regular file", fakeFileInfo{name: "listener.sock", mode: 0o600, sys: &syscall.Stat_t{Uid: 1000}}, lu},
		{"dir owned by another uid", fakeFileInfo{name: "auth-agent1", mode: 0o700 | os.ModeDir, sys: &syscall.Stat_t{Uid: 0}}, lu},
		{"dir without stat owner", fakeFileInfo{name: "auth-agent1", mode: 0o700 | os.ModeDir, sys: struct{}{}}, lu},
	} {
		err := checkAgentDirRemovable(tt.fi, tt.lu)
		if err == nil {
			t.Errorf("checkAgentDirRemovable(%s) = nil, want an error", tt.name)
		}
	}
}
