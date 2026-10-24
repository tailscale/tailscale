// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// The monitor-backed forwarding paths. On unix, all forwarded sockets are
// dialed and bound by one-shot children of the per-connection ssh-monitor
// running with the authenticated local user's credentials.
//
//   - unix -L, direct-streamlocal: the lexical allowlist check stays in
//     tailscaled as coarse policy, then the dial runs as the user. See
//     conn.fwdAllowedSocketPath for the path policy.
//   - unix -R, streamlocal-forward: the listener child binds with
//     umask-at-bind and unlink-if-owned semantics. The socket is 0600 and
//     user-owned from the moment it exists.
//   - TCP -R, tcpip-forward: the bind goes through the monitor's listen
//     op, run by a user-cred listener child. Privileged ports fail with
//     EACCES for non-root-mapped users. Bind addresses are
//     loopback-only unless TS_SSH_FORWARD_GATEWAY_PORTS is set.
//   - agent forwarding: the socket and its containing directory are
//     created by a user-cred child. The socket is 0600 in a 0700
//     user-owned directory.
//

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"tailscale.com/types/logger"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
)

// fwdState is the conn's monitor state. It holds the per-connection
// ssh-monitor, spawned lazily on the first forwarding, agent, or
// session need and closed when the conn is torn down. exits
// dispatches the monitor's async child-exit notifications to the
// conn's sessions in sessmonitor.go. The monitor's identity is bound at
// spawn to the conn's localUser, with the uid, gid, and groups from
// clientAuth.
type fwdState struct {
	mu  sync.Mutex
	mon *monitorClient

	// closed is set by closeFwdMonitor, before the lock is dropped. Once
	// the conn's teardown has run, fwdMonitor refuses to spawn.
	// fwdMonitorIfAny is unaffected.
	closed bool

	// exits routes notifications by child handle. Its callback is installed
	// at monitor spawn.
	exits monExitRegistry
}

// monExitRegistry matches exit notifications to child handles, including
// notifications received before the session registers its waiter.
type monExitRegistry struct {
	mu      sync.Mutex
	waiters map[monitorProcess]*monExitStatus
	pending map[monitorProcess]int // exits received before registration
}

// dispatchExit is the monitorClient exit callback, called from the
// client's read-loop goroutine.
func (s *monExitRegistry) dispatchExit(pid monitorProcess, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.waiters[pid]; ok {
		delete(s.waiters, pid)
		ch.complete(code)
		return
	}
	if s.pending == nil {
		s.pending = make(map[monitorProcess]int)
	}
	s.pending[pid] = code
}

// registerSessionExit delivers and removes a pending exit, or registers
// a waiter for a future notification.
func (s *monExitRegistry) registerSessionExit(pid monitorProcess, ch *monExitStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if code, ok := s.pending[pid]; ok {
		delete(s.pending, pid)
		ch.complete(code)
		return
	}
	if s.waiters == nil {
		s.waiters = make(map[monitorProcess]*monExitStatus)
	}
	s.waiters[pid] = ch
}

// fwdMonitor returns the conn's monitor, spawning it on first use with
// the spawn-bound identity documented on fwdState.
func (c *conn) fwdMonitor() (*monitorClient, error) {
	c.fwd.mu.Lock()
	defer c.fwd.mu.Unlock()
	if c.fwd.mon != nil {
		return c.fwd.mon, nil
	}
	if c.fwd.closed {
		return nil, errors.New("monitor closed at connection teardown")
	}
	uid, gid, groups, err := c.fwdCreds()
	if err != nil {
		return nil, err
	}
	// The monitor is exec'd from the tailscaled binary; in tests
	// os.Executable() is the test binary. The incubator spawn takes the
	// same path from srv.tailscaledPath.
	exe := c.srv.tailscaledPath
	if exe == "" {
		exe, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("ssh-monitor: executable: %w", err)
		}
	}
	mc, err := spawnMonitor(exe, uid, gid, groups, c.localUser.Username)
	if err != nil {
		return nil, fmt.Errorf("spawning ssh-monitor for %q: %w", c.localUser.Username, err)
	}
	// Route the monitor's async exit notifications to the conn's
	// sessions in sessmonitor.go.
	mc.SetExitCallback(c.fwd.exits.dispatchExit)
	c.fwd.mon = mc
	return mc, nil
}

// fwdMonitorIfAny returns the conn's monitor without spawning one.
// Callers that can race the conn's teardown must use it instead of the
// lazy fwdMonitor. See fwdState.closed.
func (c *conn) fwdMonitorIfAny() *monitorClient {
	c.fwd.mu.Lock()
	defer c.fwd.mu.Unlock()
	return c.fwd.mon
}

// fwdCreds returns the monitor's spawn identity, parsing like the
// incubator's argv does. The ids are carried at their 32-bit ABI width.
func (c *conn) fwdCreds() (uid, gid uint32, groups []uint32, err error) {
	u64, err := strconv.ParseUint(c.localUser.Uid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("forwarding: parsing local user uid %q: %w", c.localUser.Uid, err)
	}
	g64, err := strconv.ParseUint(c.localUser.Gid, 10, 32)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("forwarding: parsing local user gid %q: %w", c.localUser.Gid, err)
	}
	for _, g := range c.userGroupIDs {
		v, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("forwarding: parsing local user group %q: %w", g, err)
		}
		groups = append(groups, uint32(v))
	}
	return uint32(u64), uint32(g64), groups, nil
}

// closeFwdMonitor closes the conn's monitor, if one was spawned. It
// runs from HandleSSHConn's defer after the SSH connection is done.
// Closing the RPC channel triggers the monitor's teardown in monitor.go.
// Closing a second time is a no-op.
func (c *conn) closeFwdMonitor() {
	c.fwd.mu.Lock()
	mc := c.fwd.mon
	c.fwd.mon = nil
	c.fwd.closed = true
	c.fwd.mu.Unlock()
	if mc == nil {
		return
	}
	if err := mc.Close(); err != nil {
		c.logf("ssh: closing forwarding monitor: %v", err)
	}
}

// fwdMaxSunPathLen is the sun_path capacity. It is the lexical length
// cap on unix socket paths, the same one gliderssh's path validator
// enforced. The cap is 108 on Linux and 104 on macOS.
var fwdMaxSunPathLen = len(unix.RawSockaddrUnix{}.Path)

// fwdAllowedSocketPath applies the lexical socket-path allowlist and
// returns the cleaned path to dial or bind. The allowlist is the same one
// gliderssh's UnixForwardingOptions enforced: the user's home directory,
// /tmp, and /run/user/<uid>. Relative paths and abstract socket names
// (a leading "@") are rejected.
func (c *conn) fwdAllowedSocketPath(socketPath string) (string, error) {
	if !filepath.IsAbs(socketPath) || strings.HasPrefix(socketPath, "@") || strings.ContainsRune(socketPath, 0) {
		return "", fmt.Errorf("socket path %q must be an absolute filesystem path: %w", socketPath, gliderssh.ErrRejected)
	}
	cleaned := filepath.Clean(socketPath)
	// The sun_path length cap rejects over-long paths lexically, per
	// fwdMaxSunPathLen.
	if len(cleaned) >= fwdMaxSunPathLen {
		return "", fmt.Errorf("socket path too long (%d >= %d): %w", len(cleaned), fwdMaxSunPathLen, gliderssh.ErrRejected)
	}
	for _, dir := range []string{c.localUser.HomeDir, "/tmp", filepath.Join("/run/user", c.localUser.Uid)} {
		prefix := filepath.Clean(dir)
		if dir == "" || prefix == string(filepath.Separator) {
			// A home dir of "/" cleans to the separator itself, whose prefix
			// matches every absolute path and collapses the coarse
			// allowlist to "any absolute path". Drop the entry.
			continue
		}
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if strings.HasPrefix(cleaned, prefix) {
			return cleaned, nil
		}
	}
	return "", fmt.Errorf("socket path %q is not in an allowed directory: %w", cleaned, gliderssh.ErrRejected)
}

// fwdDialUnix is the unix -L path (direct-streamlocal): dial socketPath
// through a one-shot child with the local user's credentials.
func (c *conn) fwdDialUnix(ctx gliderssh.Context, socketPath string) (net.Conn, error) {
	path, err := c.fwdAllowedSocketPath(socketPath)
	if err != nil {
		return nil, err
	}
	mc, err := c.fwdMonitor()
	if err != nil {
		return nil, err
	}
	uc, err := mc.Dial(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("dial unix socket %q: %w", path, err)
	}
	return uc, nil
}

// fwdListenUnix is the unix -R path, streamlocal-forward. It listens at
// socketPath through a one-shot child with the local user's credentials,
// umasking before the bind so the socket is created directly at 0600
// user-owned, and unlinking an existing socket only when the session uid
// owns it. Closing the returned listener does not unlink the socket
// file; a canceled forward may leave a stale socket that the next bind's
// unlink-if-owned reclaims.
func (c *conn) fwdListenUnix(ctx gliderssh.Context, socketPath string) (net.Listener, error) {
	path, err := c.fwdAllowedSocketPath(socketPath)
	if err != nil {
		return nil, err
	}
	mc, err := c.fwdMonitor()
	if err != nil {
		return nil, err
	}
	return mc.Listen(ctx, "unix", path, true) // unlink: if-owned
}

// fwdListenAgent returns the agent-forwarding listener and socket path,
// both created by a child with the local user's credentials: a 0700
// user-owned temp dir and, inside it, a 0600 user-owned socket. Removing
// the directory is the caller's job at session end. lu is the session's
// local user, unused on unix.
func (c *conn) fwdListenAgent(ctx gliderssh.Context, lu *userMeta) (net.Listener, string, error) {
	_ = lu
	mc, err := c.fwdMonitor()
	if err != nil {
		return nil, "", err
	}
	return mc.ListenAgent(ctx)
}

// fwdTCPHandler is tailssh's replacement for gliderssh's
// ForwardedTCPHandler, serving "tcpip-forward" and
// "cancel-tcpip-forward". The bind goes through the conn's monitor, so
// the listener is created by a child bound to the local user's
// credentials; privileged ports below 1024 fail with EACCES for
// non-root-mapped users. Bind addresses are loopback-only unless
// sshForwardGatewayPorts is set.
type fwdTCPHandler struct {
	conn *conn

	mu       sync.Mutex
	forwards map[string]net.Listener
}

// The remote-forward request and channel payloads of RFC 4254 §7.
type fwdRemoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type fwdRemoteForwardSuccess struct {
	BindPort uint32
}

type fwdRemoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type fwdRemoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// fwdLoopbackBindAddr reports the bind address to use for a reverse TCP
// forward and whether the requested one is permitted. Only loopback is
// allowed, 127.0.0.0/8 and ::1, unless TS_SSH_FORWARD_GATEWAY_PORTS is
// set. An empty address binds 127.0.0.1. The listener resolves
// "localhost".
func fwdLoopbackBindAddr(bindAddr string) (string, bool) {
	if sshForwardGatewayPorts() {
		return bindAddr, true
	}
	switch bindAddr {
	case "":
		// ssh(1) documents -R without an address as binding loopback. Bind
		// it explicitly so the listener is unambiguous.
		return "127.0.0.1", true
	case "localhost":
		return bindAddr, true
	}
	if ip := net.ParseIP(bindAddr); ip != nil && ip.IsLoopback() {
		return bindAddr, true
	}
	return "", false
}

// HandleSSHRequest serves tcpip-forward and cancel-tcpip-forward. The
// bind-address policy and the monitor bind live here.
func (h *fwdTCPHandler) HandleSSHRequest(ctx gliderssh.Context, _ *gliderssh.Server, req *gossh.Request) (bool, []byte) {
	h.mu.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]net.Listener)
	}
	h.mu.Unlock()
	sshConn, ok := ctx.Value(gliderssh.ContextKeyConn).(gossh.Conn)
	if !ok {
		return false, nil
	}
	switch req.Type {
	case "tcpip-forward":
		var reqPayload fwdRemoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			return false, nil
		}
		if !h.conn.mayReversePortForwardTo(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		bindAddr, ok := fwdLoopbackBindAddr(reqPayload.BindAddr)
		if !ok {
			return false, []byte("binding to non-loopback addresses is not permitted")
		}
		mc, err := h.conn.fwdMonitor()
		if err != nil {
			h.conn.logf("ssh: reverse port forward: %v", err)
			return false, []byte{}
		}
		ln, err := mc.Listen(ctx, "tcp", net.JoinHostPort(bindAddr, strconv.Itoa(int(reqPayload.BindPort))), false)
		if err != nil {
			// A privileged port under a non-root bound identity fails the
			// bind with EACCES.
			h.conn.logf("ssh: reverse port forward bind %s:%d: %v", reqPayload.BindAddr, reqPayload.BindPort, err)
			return false, []byte{}
		}

		// If the bind port was 0, use the actual port in the forwards map.
		destPort := reqPayload.BindPort
		if tl, ok := ln.Addr().(*net.TCPAddr); ok {
			destPort = uint32(tl.Port)
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(destPort)))
		h.mu.Lock()
		h.forwards[addr] = ln
		h.mu.Unlock()
		go func() {
			<-ctx.Done()
			h.mu.Lock()
			fln, ok := h.forwards[addr]
			h.mu.Unlock()
			if ok {
				fln.Close()
			}
		}()
		go func() {
			defer func() {
				h.mu.Lock()
				if h.forwards[addr] == ln {
					delete(h.forwards, addr)
				}
				h.mu.Unlock()
				ln.Close()
			}()
			for {
				nc, err := ln.Accept()
				if err != nil {
					return
				}
				originAddr, originPortStr, _ := net.SplitHostPort(nc.RemoteAddr().String())
				originPort, _ := strconv.ParseUint(originPortStr, 10, 16)
				payload := gossh.Marshal(&fwdRemoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   destPort,
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				go func() {
					ch, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
					if err != nil {
						nc.Close()
						return
					}
					go gossh.DiscardRequests(reqs)
					fwdBicopy(ctx, ch, nc)
				}()
			}
		}()
		return true, gossh.Marshal(&fwdRemoteForwardSuccess{destPort})

	case "cancel-tcpip-forward":
		var reqPayload fwdRemoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			return false, nil
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		h.mu.Lock()
		ln, ok := h.forwards[addr]
		if ok {
			delete(h.forwards, addr)
		}
		h.mu.Unlock()
		if ok {
			ln.Close()
		}
		return true, nil

	default:
		return false, nil
	}
}

// fwdBicopy copies data bidirectionally between c1 and c2 until both
// directions complete or the context is canceled, half-closing the write
// side of each destination on EOF (RFC 4254 §5.3).
func fwdBicopy(ctx context.Context, c1, c2 io.ReadWriteCloser) {
	defer c1.Close()
	defer c2.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		defer fwdHalfCloseWrite(c1)
		_, _ = io.Copy(c1, c2)
	})
	wg.Go(func() {
		defer fwdHalfCloseWrite(c2)
		_, _ = io.Copy(c2, c1)
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-ctx.Done():
		c1.Close()
		c2.Close()
		<-done
	}
}

// fwdHalfCloseWrite signals EOF on the write side of c if c supports
// CloseWrite, as *net.TCPConn, *net.UnixConn, and gossh.Channel do.
// Otherwise the deferred full Close in fwdBicopy handles cleanup.
func fwdHalfCloseWrite(c io.ReadWriteCloser) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// wireReverseForwarding installs the conn's reverse TCP forwarding
// request handlers. On unix they are fwdTCPHandler's, binding through
// the monitor.
func (c *conn) wireReverseForwarding(ss *gliderssh.Server) {
	h := &fwdTCPHandler{conn: c}
	ss.RequestHandlers["tcpip-forward"] = h.HandleSSHRequest
	ss.RequestHandlers["cancel-tcpip-forward"] = h.HandleSSHRequest
}

// removeAgentForwardingDir removes the agent-forwarding directory dir at
// session end. The removal runs with the daemon's credentials while dir
// and everything in it belong to the connection's user, so a hostile
// user must not steer it. It is refused unless dir is still a directory
// directly under agentDirRoot, and agentDirRoot is itself root-owned, so
// no component of the path can be swapped for a symlink by the session
// user. The removal is resolved relative to a pinned handle on
// agentDirRoot, which follows no symlinks in the name or below it. If
// the checked directory was swapped for a user-owned one between the
// check and the removal, what is removed is still only a user-owned
// entry in agentDirRoot, which the user can remove itself. Failures are
// logged, never fatal: a leftover temp dir is the fallback.
func removeAgentForwardingDir(dir string, lu *userMeta, logf logger.Logf) {
	if filepath.Dir(dir) != agentDirRoot || !strings.HasPrefix(filepath.Base(dir), "auth-agent") {
		logf("ssh: refusing to remove agent forwarding dir %s: not an auth-agent directory directly inside %s", dir, agentDirRoot)
		return
	}
	fi, err := os.Stat(agentDirRoot)
	if err != nil {
		logf("ssh: agent forwarding dir root %s: %v", agentDirRoot, err)
		return
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logf("ssh: refusing to remove agent forwarding dir %s: %s owner not available", dir, agentDirRoot)
		return
	}
	if st.Uid != 0 {
		logf("ssh: refusing to remove agent forwarding dir %s: %s is not root-owned", dir, agentDirRoot)
		return
	}
	r, err := os.OpenRoot(agentDirRoot)
	if err != nil {
		logf("ssh: agent forwarding dir root %s: %v", agentDirRoot, err)
		return
	}
	defer r.Close()
	name := filepath.Base(dir)
	fi, err = r.Lstat(name)
	if err != nil {
		if !os.IsNotExist(err) {
			logf("ssh: agent forwarding dir %s: %v", dir, err)
		}
		return
	}
	if err := checkAgentDirRemovable(fi, lu); err != nil {
		logf("ssh: refusing to remove agent forwarding dir %s: %v", dir, err)
		return
	}
	if err := r.RemoveAll(name); err != nil {
		logf("ssh: removing agent forwarding dir: %v", err)
	}
}

// checkAgentDirRemovable verifies one agent-forwarding directory before
// its root-run removal: a directory (never a symlink), owned by the
// connection's user, with no group or other permission bits — the shape
// MkdirTemp leaves behind.
func checkAgentDirRemovable(fi os.FileInfo, lu *userMeta) error {
	if !fi.Mode().IsDir() {
		return errors.New("agent forwarding dir is not a directory")
	}
	uid, err := strconv.ParseUint(lu.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("agent forwarding dir: parsing bound uid %q: %w", lu.Uid, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("agent forwarding dir: owner not available")
	}
	if st.Uid != uint32(uid) {
		return fmt.Errorf("agent forwarding dir owned by uid %d, want %d", st.Uid, uid)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("agent forwarding dir mode %04o is group- or other-accessible", fi.Mode().Perm())
	}
	return nil
}
