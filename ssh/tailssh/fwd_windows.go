// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The Windows forwarding seam.
//
// Windows has no per-connection monitor process. Instead tailssh dials and
// binds forwarded TCP sockets itself, impersonating the connection's user
// for the socket, connect, and bind operations through conn.fwdImpersonate
// (see connmonitor_windows.go). That gives those sockets the user's
// identity for Windows Filtering Platform rules, as the unix monitor's
// user-credential children do, without a separate process. The socket's
// owning process is still tailscaled, so a connection-to-PID lookup names
// tailscaled; impersonation changes the identity the firewall authorizes,
// not process ownership.
//
// Unix socket forwarding and agent forwarding are not offered:
//
//   - Unix socket forwarding (ssh -L/-R to an AF_UNIX path): the per-user
//     socket directories the unix rules allow do not exist on Windows.
//   - Agent forwarding: the socket and its SSH_AUTH_SOCK convention are
//     Unix-only. OpenSSH for Windows forwards the agent over a named pipe
//     instead, which gliderssh does not model. Supporting it would need a
//     named-pipe agent listener and is left for later; see fwdListenAgent.

package tailssh

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
	"sync"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"

	"tailscale.com/types/logger"
)

var errUnixForwardingUnsupported = errors.New("Unix socket forwarding is not supported on Windows")

// fwdDialUnix is the unix -L path (direct-streamlocal). It is refused on
// Windows; see the file comment.
func (c *conn) fwdDialUnix(ctx gliderssh.Context, socketPath string) (net.Conn, error) {
	return nil, errUnixForwardingUnsupported
}

// fwdListenUnix is the unix -R path (streamlocal-forward). It is refused on
// Windows; see the file comment.
func (c *conn) fwdListenUnix(ctx gliderssh.Context, socketPath string) (net.Listener, error) {
	return nil, errUnixForwardingUnsupported
}

// fwdListenAgent would return the agent-forwarding listener and socket
// path. Agent forwarding is not supported on Windows; see the file
// comment for what adding it would take.
func (c *conn) fwdListenAgent(ctx gliderssh.Context, lu *userMeta) (net.Listener, string, error) {
	return nil, "", errors.New("agent forwarding is not supported on Windows")
}

// removeAgentForwardingDir is a no-op on Windows, which never creates an
// agent forwarding directory.
func removeAgentForwardingDir(dir string, lu *userMeta, logf logger.Logf) {}

// wireForwarding installs the Windows direct and reverse TCP forwarding
// handlers. Both dial and bind as the connection's user through
// conn.fwdImpersonate. Unlike plan9, Windows does not use gliderssh's
// default handlers, which would dial and bind as LocalSystem.
func (c *conn) wireForwarding(ss *gliderssh.Server) {
	ss.ChannelHandlers["direct-tcpip"] = c.fwdDirectTCPIPHandler
	h := &winFwdTCPHandler{conn: c}
	ss.RequestHandlers["tcpip-forward"] = h.HandleSSHRequest
	ss.RequestHandlers["cancel-tcpip-forward"] = h.HandleSSHRequest
}

// fwdDirectTCPIPHandler serves TCP -L and SOCKS -D forwards, both
// direct-tcpip channels. Policy is checked before the dial, and the dial
// runs as the connection's user. The forwarding request supplies no user
// identity and cannot change the credentials chosen at authentication.
func (c *conn) fwdDirectTCPIPHandler(srv *gliderssh.Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx gliderssh.Context) {
	var d struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}
	if d.DestPort == 0 || d.DestPort > math.MaxUint16 {
		newChan.Reject(gossh.ConnectionFailed, "destination port must be between 1 and 65535")
		return
	}
	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}
	dest := net.JoinHostPort(d.DestAddr, strconv.FormatUint(uint64(d.DestPort), 10))
	var dconn net.Conn
	var dialErr error
	if err := c.fwdImpersonate(func() {
		var dialer net.Dialer
		dconn, dialErr = dialer.DialContext(ctx, "tcp", dest)
	}); err != nil {
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	if dialErr != nil {
		newChan.Reject(gossh.ConnectionFailed, dialErr.Error())
		return
	}
	fwdAcceptAndBicopy(ctx, newChan, dconn)
}

// winFwdTCPHandler serves "tcpip-forward" and "cancel-tcpip-forward" (TCP
// -R). The bind runs as the connection's user, so a port the user may not
// bind fails by Windows' own check rather than succeeding as LocalSystem.
// Bind addresses are loopback-only unless TS_SSH_FORWARD_GATEWAY_PORTS is
// set. It mirrors the unix fwdTCPHandler without the monitor.
type winFwdTCPHandler struct {
	conn *conn

	mu       sync.Mutex
	forwards map[string]net.Listener
}

// HandleSSHRequest serves tcpip-forward and cancel-tcpip-forward.
func (h *winFwdTCPHandler) HandleSSHRequest(ctx gliderssh.Context, _ *gliderssh.Server, req *gossh.Request) (bool, []byte) {
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
		listenAddr := net.JoinHostPort(bindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		var ln net.Listener
		var lnErr error
		if err := h.conn.fwdImpersonate(func() {
			var lc net.ListenConfig
			ln, lnErr = lc.Listen(ctx, "tcp", listenAddr)
		}); err != nil {
			h.conn.logf("ssh: reverse port forward: %v", err)
			return false, []byte{}
		}
		if lnErr != nil {
			h.conn.logf("ssh: reverse port forward bind %s:%d: %v", reqPayload.BindAddr, reqPayload.BindPort, lnErr)
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
		// Close this listener when the SSH connection ends. Stop watching the
		// connection when the accept loop exits, including on cancellation of
		// this forward while the connection remains open.
		stop := context.AfterFunc(ctx, func() { ln.Close() })
		go func() {
			defer stop()
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
