// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

// The plan9 forwarding seam. plan9 keeps today's forwarding behavior:
// tailscaled binds and dials forwarded sockets itself, with no monitor
// because SysProcAttr.Credential and SCM_RIGHTS are unavailable. Reverse
// TCP forwarding keeps gliderssh's ForwardedTCPHandler with the
// mayReversePortForwardTo policy callback.

package tailssh

import (
	"net"
	"os"
	"path/filepath"
	"strconv"

	"tailscale.com/types/logger"

	gliderssh "github.com/tailscale/gliderssh"
)

// fwdState is the conn's forwarding state. On plan9 there is no monitor,
// so it carries nothing.
type fwdState struct{}

// fwdDialUnix is the unix -L path. The gliderssh callback rejects on
// plan9. See the file comment.
func (c *conn) fwdDialUnix(ctx gliderssh.Context, socketPath string) (net.Conn, error) {
	cb := gliderssh.NewLocalUnixForwardingCallback(c.unixForwardingOptions())
	return cb(ctx, socketPath)
}

// fwdListenUnix is the unix -R path. The gliderssh callback rejects on
// plan9. See the file comment.
func (c *conn) fwdListenUnix(ctx gliderssh.Context, socketPath string) (net.Listener, error) {
	cb := gliderssh.NewReverseUnixForwardingCallback(c.unixForwardingOptions())
	return cb(ctx, socketPath)
}

// fwdListenAgent returns the agent-forwarding listener and socket path.
// plan9 keeps today's behavior. tailscaled creates the socket with
// gliderssh.NewAgentListener and hands it, and its containing directory,
// to the session user with explicit chmod/chown.
func (c *conn) fwdListenAgent(ctx gliderssh.Context, lu *userMeta) (net.Listener, string, error) {
	ln, err := gliderssh.NewAgentListener()
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err != nil && ln != nil {
			ln.Close()
		}
	}()

	// 31 bits so that the values fit an int on every platform.
	uid, err := strconv.ParseUint(lu.Uid, 10, 31)
	if err != nil {
		return nil, "", err
	}
	gid, err := strconv.ParseUint(lu.Gid, 10, 31)
	if err != nil {
		return nil, "", err
	}
	socket := ln.Addr().String()
	dir := filepath.Dir(socket)
	// Hand the socket and its containing directory to the user, like
	// sshd's agent forwarding. The dir stays 0700 as MkdirTemp created it
	// until the socket is in place and owned by the user, then it is
	// chowned to the user too so the session can reach its socket.
	if err := os.Chmod(socket, 0o600); err != nil {
		return nil, "", err
	}
	if err := os.Chown(socket, int(uid), int(gid)); err != nil {
		return nil, "", err
	}
	if err := os.Chown(dir, int(uid), int(gid)); err != nil {
		return nil, "", err
	}
	// Defensively restore the 0700 mode.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, "", err
	}
	return ln, socket, nil
}

// removeAgentForwardingDir removes the agent-forwarding directory dir.
// plan9 has no monitor: tailscaled created the directory itself and
// handed it to the session user, and the removal runs with the same
// credentials, so there is no privilege boundary to defend.
func removeAgentForwardingDir(dir string, lu *userMeta, logf logger.Logf) {
	if err := os.RemoveAll(dir); err != nil {
		logf("ssh: removing agent forwarding dir: %v", err)
	}
}

// closeFwdMonitor is a no-op on plan9 because there is no monitor.
func (c *conn) closeFwdMonitor() {}

// wireReverseForwarding installs plan9's reverse TCP forwarding
// handlers. They are today's gliderssh ForwardedTCPHandler plus the
// mayReversePortForwardTo policy callback.
func (c *conn) wireReverseForwarding(ss *gliderssh.Server) {
	ss.ReversePortForwardingCallback = c.mayReversePortForwardTo
	fwdHandler := &gliderssh.ForwardedTCPHandler{}
	ss.RequestHandlers["tcpip-forward"] = fwdHandler.HandleSSHRequest
	ss.RequestHandlers["cancel-tcpip-forward"] = fwdHandler.HandleSSHRequest
}

// unixForwardingOptions returns the Unix forwarding options scoped to
// the authenticated local user. Socket paths are restricted to the
// user's home directory, /tmp, and /run/user/<uid>.
func (c *conn) unixForwardingOptions() gliderssh.UnixForwardingOptions {
	return gliderssh.UnixForwardingOptions{
		AllowedDirectories: gliderssh.UserSocketDirectories(c.localUser.HomeDir, c.localUser.Uid),
		BindUnlink:         true,
	}
}
