// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// Register installs tailssh's hooks and child process handlers. It is
// called from the init of tailscale.com/feature/ssh, which skips it if
// the ssh feature was disabled via TS_DISABLE_FEATURE or omitted from
// the build.
func Register() {
	ipnlocal.HookListenSSH.Set(listenSSH)
	registerIncubator()
}

// listenSSH returns an SSH server that wraps rawLn. The returned
// listener's Accept yields each session as a *Session. A nil auth
// accepts every session. A non-nil auth is called for each session
// with the peer identity, and a session that auth rejects is refused.
func listenSSH(rawLn net.Listener, lb *ipnlocal.LocalBackend, auth ipnlocal.SSHAuthCallback, logf logger.Logf) (net.Listener, error) {
	return newSSHListener(rawLn, sshListenerConfig{
		varRoot: lb.TailscaleVarRoot(),
		whoIs:   lb.WhoIs,
		auth:    auth,
		logf:    logf,
	})
}

// sshListenerConfig holds the dependencies of the SSH listener.
// listenSSH fills it in from a LocalBackend, and tests use a stub
// whoIs instead.
type sshListenerConfig struct {
	varRoot string
	whoIs   func(proto string, ipp netip.AddrPort) (node tailcfg.NodeView, userProfile tailcfg.UserProfile, ok bool)
	auth    ipnlocal.SSHAuthCallback // or nil to accept all peers
	logf    logger.Logf
}

// newSSHListener serves SSH on rawLn. The returned listener's Accept
// method yields each session as a *Session, and each session is also
// usable as a net.Conn.
//
// The server runs session channels only, and accepts connections
// without SSH client authentication. It resolves each connecting peer
// with cfg.whoIs and refuses sessions from peers that do not resolve.
// If cfg.auth is set, it refuses sessions that cfg.auth rejects as
// well. Sessions are not mapped to a local user and are not recorded.
// The application consuming the sessions from Accept is responsible
// for anything further.
func newSSHListener(rawLn net.Listener, cfg sshListenerConfig) (net.Listener, error) {
	hostKeys, err := getHostKeys(cfg.varRoot, cfg.logf)
	if err != nil {
		return nil, err
	}
	signers := make([]gliderssh.Signer, len(hostKeys))
	for i, k := range hostKeys {
		signers[i] = k
	}

	sl := &sshListener{
		cfg:      cfg,
		rawLn:    rawLn,
		sessions: make(chan net.Conn, maxQueuedSSHListenerSessions),
		done:     make(chan struct{}),
	}

	sshSrv := &gliderssh.Server{
		HostSigners:      signers,
		HandshakeTimeout: loginGraceTime(),
		IdleTimeout:      sshIdleTimeout(),
		Handler:          sl.handleSession,
	}
	sl.sshSrv = sshSrv

	go func() {
		if err := sshSrv.Serve(rawLn); err != nil {
			// Serve returns when the listener is closed. Only log
			// unexpected errors.
			select {
			case <-sl.done:
			default:
				cfg.logf("listenSSH: Serve error: %v", err)
			}
		}
		sl.Close()
	}()

	return sl, nil
}

// maxQueuedSSHListenerSessions is the number of sessions that may
// wait in the listener queue before new sessions are refused.
const maxQueuedSSHListenerSessions = 16

// handleSession resolves the peer identity, calls cfg.auth when set,
// and queues the session for Accept.
func (sl *sshListener) handleSession(sess gliderssh.Session) {
	// The application reads and writes the session as a plain
	// net.Conn. Disable the terminal emulation that translates "\n" to
	// "\r\n" on PTY sessions, so that writes pass through unchanged.
	sess.DisablePTYEmulation()

	srcAddr := sess.RemoteAddr().String()
	ipp, err := netip.ParseAddrPort(srcAddr)
	if err != nil {
		sl.cfg.logf("listenSSH: bad remote addr %q: %v", srcAddr, err)
		sess.Exit(1)
		return
	}
	node, userProfile, ok := sl.cfg.whoIs("tcp", ipp)
	if !ok {
		sl.cfg.logf("listenSSH: WhoIs failed for %v", srcAddr)
		sess.Exit(1)
		return
	}
	if sl.cfg.auth != nil && !sl.cfg.auth(node, userProfile) {
		sl.cfg.logf("listenSSH: session from %v rejected by authorization callback", srcAddr)
		sess.Exit(1)
		return
	}

	done := make(chan struct{})
	s := newSession(sess, peerIdentity{
		Node:        node,
		UserProfile: userProfile,
	}, done)

	// Queue the session for Accept. A closed listener drops the
	// session, and a full queue refuses it, so that at most
	// maxQueuedSSHListenerSessions sessions wait for Accept.
	select {
	case sl.sessions <- s:
	case <-sl.done:
		sess.Exit(1)
		return
	default:
		sl.cfg.logf("listenSSH: session queue full (%d); refusing session from %v", maxQueuedSSHListenerSessions, srcAddr)
		sess.Exit(1)
		return
	}

	// Block until the consumer is done with the session.
	select {
	case <-done:
	case <-sess.Context().Done():
	case <-sl.done:
		sess.Exit(1)
	}
}

// sshListener is a net.Listener that yields *Session values from its Accept
// method. It wraps a raw TCP listener with an SSH server.
type sshListener struct {
	cfg       sshListenerConfig
	sshSrv    *gliderssh.Server
	rawLn     net.Listener
	sessions  chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

// Accept returns the next SSH session as a net.Conn. The returned value can
// be type-asserted to *Session.
func (sl *sshListener) Accept() (net.Conn, error) {
	select {
	case s, ok := <-sl.sessions:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return s, nil
	case <-sl.done:
		return nil, errors.New("listener closed")
	}
}

// Close closes the underlying raw listener and signals all pending sessions
// to terminate.
func (sl *sshListener) Close() error {
	var err error
	sl.closeOnce.Do(func() {
		close(sl.done)
		err = sl.rawLn.Close()
		// Server.Close also closes rawLn and closes the tracked
		// connections, so open SSH connections do not outlive the
		// listener.
		sl.sshSrv.Close()
	})
	return err
}

// Addr returns the address of the underlying raw listener.
func (sl *sshListener) Addr() net.Addr {
	return sl.rawLn.Addr()
}

// sshIdleTimeoutRaw is the raw value of the TS_SSH_IDLE_TIMEOUT knob.
var sshIdleTimeoutRaw = envknob.RegisterString("TS_SSH_IDLE_TIMEOUT")

// sshIdleTimeout is the maximum time an SSH connection may go without
// traffic before it is closed, set by TS_SSH_IDLE_TIMEOUT. The default
// is 0, and zero means there is no idle timeout.
func sshIdleTimeout() time.Duration {
	if d, ok := parseDurationOrSeconds(sshIdleTimeoutRaw()); ok {
		return max(d, 0)
	}
	return 0
}

// loginGraceTime returns the maximum allowed duration between accepting
// a connection and completing authentication, like sshd's LoginGraceTime.
// TS_SSH_LOGIN_GRACE_TIME overrides the default of 120 seconds. An
// invalid value uses the default.
func loginGraceTime() time.Duration {
	if d, ok := parseDurationOrSeconds(sshLoginGraceTime()); ok && d > 0 {
		return d
	}
	return 120 * time.Second
}

// parseDurationOrSeconds parses a Go duration such as "90s", or a bare
// number of seconds such as "90".
func parseDurationOrSeconds(v string) (time.Duration, bool) {
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, true
	}
	return 0, false
}
