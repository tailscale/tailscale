// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The Windows forwarding seam. Windows has no process monitor: TCP
// forwarding is done by tailscaled itself with gliderssh's handlers, as on
// plan9. Unix socket forwarding and agent forwarding are not offered. The
// per-user socket directories the Unix rules allow don't exist on Windows,
// and OpenSSH for Windows's ssh-agent listens on a named pipe rather than
// an SSH_AUTH_SOCK socket, so there is nothing a forwarded socket could
// plug into.

package tailssh

import (
	"errors"
	"net"

	gliderssh "github.com/tailscale/gliderssh"
	"tailscale.com/types/logger"
)

var errUnixForwardingUnsupported = errors.New("Unix socket forwarding is not supported on Windows")

// fwdDialUnix is the unix -L path. It is refused on Windows.
func (c *conn) fwdDialUnix(ctx gliderssh.Context, socketPath string) (net.Conn, error) {
	return nil, errUnixForwardingUnsupported
}

// fwdListenUnix is the unix -R path. It is refused on Windows.
func (c *conn) fwdListenUnix(ctx gliderssh.Context, socketPath string) (net.Listener, error) {
	return nil, errUnixForwardingUnsupported
}

// fwdListenAgent would return the agent-forwarding listener. Agent
// forwarding is not supported on Windows; see the file comment.
func (c *conn) fwdListenAgent(ctx gliderssh.Context, lu *userMeta) (net.Listener, string, error) {
	return nil, "", errors.New("agent forwarding is not supported on Windows")
}

// removeAgentForwardingDir is a no-op on Windows, which never creates an
// agent forwarding directory.
func removeAgentForwardingDir(dir string, lu *userMeta, logf logger.Logf) {}

// wireForwarding installs the reverse TCP forwarding handlers: gliderssh's
// ForwardedTCPHandler plus the mayReversePortForwardTo policy callback,
// as on plan9.
func (c *conn) wireForwarding(ss *gliderssh.Server) {
	ss.ReversePortForwardingCallback = c.mayReversePortForwardTo
	fwdHandler := &gliderssh.ForwardedTCPHandler{}
	ss.RequestHandlers["tcpip-forward"] = fwdHandler.HandleSSHRequest
	ss.RequestHandlers["cancel-tcpip-forward"] = fwdHandler.HandleSSHRequest
}
