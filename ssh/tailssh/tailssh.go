// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	stduser "os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/backoff"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/httpm"
	"tailscale.com/util/mak"
	"tailscale.com/version/distro"
)

var (
	sshVerboseLogging    = envknob.RegisterBool("TS_DEBUG_SSH_VLOG")
	sshDisableSFTP       = envknob.RegisterBool("TS_SSH_DISABLE_SFTP")
	sshDisableForwarding = envknob.RegisterBool("TS_SSH_DISABLE_FORWARDING")
	// sshForwardGatewayPorts permits reverse TCP forwards to bind
	// non-loopback addresses. It is the equivalent of sshd's GatewayPorts.
	sshForwardGatewayPorts = envknob.RegisterBool("TS_SSH_FORWARD_GATEWAY_PORTS")
	sshDisablePTY          = envknob.RegisterBool("TS_SSH_DISABLE_PTY")

	// sshLoginGraceTime is the TS_SSH_LOGIN_GRACE_TIME knob. It is
	// the maximum allowed duration between accepting a connection and
	// completing authentication, like sshd's LoginGraceTime. It defaults
	// to 120 seconds. See loginGraceTime for the accepted value forms.
	sshLoginGraceTime = envknob.RegisterString("TS_SSH_LOGIN_GRACE_TIME")

	// errTerminal is an empty ssh.PartialSuccessError (with no 'Next'
	// authentication methods that may proceed), which results in the SSH
	// server immediately disconnecting the client.
	errTerminal = &ssh.PartialSuccessError{}

	// hookSSHLoginSuccess is called after successful SSH authentication.
	// It is set by platform-specific code (e.g., auditd_linux.go).
	hookSSHLoginSuccess feature.Hook[func(logf logger.Logf, c *conn)]
)

const (
	// forcePasswordSuffix is the suffix at the end of a username that forces
	// Tailscale SSH into password authentication mode to work around buggy SSH
	// clients that get confused by successful replies to auth type "none".
	forcePasswordSuffix = "+password"
)

// ipnLocalBackend is the subset of ipnlocal.LocalBackend that we use.
// It is used for testing.
type ipnLocalBackend interface {
	ShouldRunSSH() bool
	NetMap() *netmap.NetworkMap
	NetMapNoPeers() *netmap.NetworkMap
	WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool)
	DoNoiseRequest(req *http.Request) (*http.Response, error)
	Dialer() *tsdial.Dialer
	TailscaleVarRoot() string
	NodeKey() key.NodePublic
}

type server struct {
	lb             ipnLocalBackend
	logf           logger.Logf
	tailscaledPath string

	timeNow func() time.Time // or nil for time.Now

	sessionWaitGroup sync.WaitGroup

	// mu protects the following
	mu             sync.Mutex
	activeConns    map[*conn]bool // set; value is always true
	shutdownCalled bool
}

func (srv *server) now() time.Time {
	if srv != nil && srv.timeNow != nil {
		return srv.timeNow()
	}
	return time.Now()
}

func init() {
	feature.HookGetSSHHostKeyPublicStrings.Set(getHostKeyPublicStrings)
	ipnlocal.RegisterC2N("/ssh/usernames", handleC2NSSHUsernames)
	ipnlocal.RegisterNewSSHServer(func(logf logger.Logf, lb *ipnlocal.LocalBackend) (ipnlocal.SSHServer, error) {
		tsd, err := os.Executable()
		if err != nil {
			return nil, err
		}
		srv := &server{
			lb:             lb,
			logf:           logf,
			tailscaledPath: tsd,
			timeNow: func() time.Time {
				return lb.ControlNow(time.Now())
			},
		}

		return srv, nil
	})
}

// attachSessionToConnIfNotShutdown ensures that srv is not shutdown before
// attaching the session to the conn. This ensures that once Shutdown is called,
// new sessions are not allowed and existing ones are cleaned up.
// It reports whether ss was attached to the conn.
func (srv *server) attachSessionToConnIfNotShutdown(ss *sshSession) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.shutdownCalled {
		// Do not start any new sessions.
		return false
	}
	ss.conn.attachSession(ss)
	return true
}

// registerConn registers c unless shutdown has started, and reports whether
// c was successfully registered. The caller must initialize c's transport
// and authentication context before calling it.
func (srv *server) registerConn(c *conn) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.shutdownCalled {
		return false
	}
	mak.Set(&srv.activeConns, c, true)
	return true
}

func (srv *server) unregisterConn(c *conn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.activeConns, c)
}

// NumActiveConns returns the number of active SSH connections.
func (srv *server) NumActiveConns() int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return len(srv.activeConns)
}

// HandleSSHConn handles a Tailscale SSH connection from c.
// This is the entry point for all SSH connections.
// When this returns, the connection is closed.
func (srv *server) HandleSSHConn(nc net.Conn) error {
	defer nc.Close()
	metricIncomingConnections.Add(1)
	c, err := srv.newConn()
	if err != nil {
		return err
	}
	// Capture the raw conn and the auth-phase context, and arm the grace
	// timer, before the conn becomes visible in activeConns: a Shutdown
	// racing the registration must find everything it needs to close the
	// conn. The handshake starts after registration.
	c.authRecheckDone = make(chan struct{})
	c.netConn = nc
	c.preAuthCtx, c.preAuthCancel = context.WithCancel(context.Background())
	c.armLoginGrace()
	if !srv.registerConn(c) {
		c.stopConnTimers()
		c.closeConn()
		return errors.New("server is shutting down")
	}
	defer srv.unregisterConn(c)
	defer c.preAuthCancel()
	defer c.stopConnTimers()
	// Close the process monitor when the SSH connection ends.
	defer c.closeConnMonitor()
	c.HandleConn(nc)

	// Return nil to signal to netstack's interception that it doesn't need to
	// log. If ss.HandleConn had problems, it can log itself (ideally on an
	// sshSession.logf).
	return nil
}

// Shutdown closes all active connections and waits for their sessions to exit.
// Closing the raw transport also interrupts authentication and cancels pending
// HoldAndDelegate requests.
func (srv *server) Shutdown() {
	srv.mu.Lock()
	srv.shutdownCalled = true
	for c := range srv.activeConns {
		c.closeConn()
	}
	srv.mu.Unlock()
	srv.sessionWaitGroup.Wait()
}

// OnPolicyChange terminates any active connections and sessions that no
// longer match the SSH access policy.
func (srv *server) OnPolicyChange() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for c := range srv.activeConns {
		if !c.authCompleted.Load() {
			// The connection hasn't completed authentication yet.
			// In that case, the connection will be terminated when it does.
			// AuthLogCallback runs a recheck on authentication success.
			continue
		}
		go c.recheckPolicy()
	}
}

// conn represents a single SSH connection and its associated
// gliderssh.Server.
//
// During the lifecycle of a connection, the following are called in order:
// Setup and discover server info
//   - ServerConfigCallback
//
// Get access to a ServerPreAuthConn (useful for sending banners)
//
// Do the user auth with a NoClientAuthCallback. If user specified
// a username ending in "+password", follow this with password auth
// (to work around buggy SSH clients that don't work with noauth).
//
// Once auth is done, the conn can be multiplexed with multiple sessions and
// channels concurrently. At which point any of the following can be called
// in any order.
//   - c.handleSessionPostSSHAuth
//   - c.mayForwardLocalPortTo followed by a credentialed TCP dial (gliderssh on plan9)
//   - c.mayForwardLocalUnixTo, the unix -L dial
//   - c.mayReverseUnixForwardTo, the unix -R bind
//   - c.wireForwarding's "tcpip-forward" handlers, the TCP -R bind
type conn struct {
	*gliderssh.Server
	srv *server

	insecureSkipTailscaleAuth bool // used by tests.

	// idH is the RFC4253 sec8 hash H. It is used to identify the connection,
	// and is shared among all sessions. It should not be shared outside
	// process. It is confusingly referred to as SessionID by the gliderlabs/ssh
	// library.
	idH    string
	connID string // ID that's shared with control

	// spac is a [ssh.ServerPreAuthConn] used for sending auth banners.
	// Banners cannot be sent after auth completes.
	spac ssh.ServerPreAuthConn

	// The following fields are set during clientAuth and are used for policy
	// evaluation and session management. They are immutable after SSH
	// authentication succeeds. They must not be read from other goroutines until
	// authCompleted is set to true.

	action0     *tailcfg.SSHAction // set by clientAuth
	finalAction *tailcfg.SSHAction // set by clientAuth

	info            *sshConnInfo // set by setInfo (during clientAuth)
	localUser       *userMeta    // set by clientAuth
	mappedLocalUser string       // policy spelling resolved to localUser at auth
	userGroupIDs    []string     // set by clientAuth
	acceptEnv       []string

	// authCompleted publishes the authentication state to policy rechecks.
	// It is set on SSH authentication success, not on an unsigned key query
	// or partial authentication success.
	authCompleted atomic.Bool

	// authRecheckDone is closed after the asynchronous auth-completion policy
	// check. It is initialized before the connection is published.
	authRecheckDone chan struct{}

	// netConn is the raw connection, captured at accept in HandleSSHConn.
	// It is set once, before HandleConn, and is read-only afterwards. It
	// exists so conn.closeConn can tear down the conn even while the SSH
	// handshake is still inside its auth callbacks, before gliderssh has
	// published the conn to its Server.
	netConn net.Conn

	// preAuthCtx lasts from accept until conn teardown and parents the
	// auth-phase HoldAndDelegate fetchSSHAction wait. preAuthCancel
	// cancels it and is set once alongside netConn.
	preAuthCtx    context.Context
	preAuthCancel context.CancelFunc

	// closeOnce makes conn.closeConn idempotent.
	closeOnce sync.Once

	// mu protects the following fields.
	//
	// srv.mu should be acquired prior to mu.
	// It is safe to just acquire mu, but unsafe to
	// acquire mu and then srv.mu.
	mu       sync.Mutex // protects the following
	sessions []*sshSession

	// recheckMu makes recheckPolicy's policy evaluation and its
	// RuleExpires timer re-arm one critical section.
	recheckMu sync.Mutex

	// graceTimer is the pre-auth login-grace timer. ruleTimer fires when
	// the currently matched rule reaches its RuleExpires. Both are
	// guarded by mu and stopped at conn teardown in HandleSSHConn.
	graceTimer *time.Timer
	ruleTimer  *time.Timer

	// teardownDone is set by stopConnTimers under mu. It prevents policy
	// rechecks from arming ruleTimer after connection cleanup.
	teardownDone bool

	// monitor owns the process monitor for sessions and forwarding.
	// It is empty on Plan 9.
	monitor connMonitorState
}

func (c *conn) logf(format string, args ...any) {
	format = fmt.Sprintf("%v: %v", c.connID, format)
	c.srv.logf(format, args...)
}

func (c *conn) vlogf(format string, args ...any) {
	if sshVerboseLogging() {
		c.logf(format, args...)
	}
}

// errDenied is returned by auth callbacks when a connection is denied by the
// policy. It writes the message to an auth banner and then returns an empty
// ssh.PartialSuccessError in order to stop processing authentication
// attempts and immediately disconnect the client.
func (c *conn) errDenied(message string) error {
	if message == "" {
		message = "tailscale: access denied"
	}
	if err := c.spac.SendAuthBanner(message); err != nil {
		c.logf("failed to send auth banner: %s", err)
	}
	return errTerminal
}

// errBanner writes the given message to an auth banner and then returns an
// empty ssh.PartialSuccessError in order to stop processing authentication
// attempts and immediately disconnect the client. The contents of err is not
// leaked in the auth banner, but it is logged to the server's log.
func (c *conn) errBanner(message string, err error) error {
	if err != nil {
		c.logf("%s: %s", message, err)
	}
	if err := c.spac.SendAuthBanner("tailscale: " + message + "\n"); err != nil {
		c.logf("failed to send auth banner: %s", err)
	}
	return errTerminal
}

// errUnexpected is returned by auth callbacks that encounter an unexpected
// error, such as being unable to send an auth banner. It sends an empty
// ssh.PartialSuccessError to tell ssh.Server to stop processing
// authentication attempts and instead disconnect immediately.
func (c *conn) errUnexpected(err error) error {
	c.logf("terminal error: %s", err)
	return errTerminal
}

// clientAuth is responsible for performing client authentication.
//
// If policy evaluation fails, it returns an error.
// If access is denied, it returns an error. This must always be an empty
// ssh.PartialSuccessError to prevent further authentication methods from
// being tried.
func (c *conn) clientAuth(cm ssh.ConnMetadata) (perms *ssh.Permissions, retErr error) {
	defer func() {
		if pse, ok := retErr.(*ssh.PartialSuccessError); ok {
			if pse.Next.GSSAPIWithMICConfig != nil ||
				pse.Next.KeyboardInteractiveCallback != nil ||
				pse.Next.PasswordCallback != nil ||
				pse.Next.PublicKeyCallback != nil {
				panic("clientAuth attempted to return a non-empty PartialSuccessError")
			}
		} else if retErr != nil {
			panic(fmt.Sprintf("clientAuth attempted to return a non-PartialSuccessError error of type: %t", retErr))
		}
	}()

	if c.insecureSkipTailscaleAuth {
		return &ssh.Permissions{}, nil
	}

	if err := c.setInfo(cm); err != nil {
		return nil, c.errBanner("failed to get connection info", err)
	}

	action, localUser, acceptEnv, _, result := c.evaluatePolicy()
	switch result {
	case accepted:
		// do nothing
	case rejectedUser:
		// The banner names the requested user: that name is the client's
		// own request and reflects only tailnet policy (the client's own
		// ACL view), never a local-host fact, so naming it leaks nothing.
		// The local-user lookup paths below must not vary with the failure
		// cause, so no banner is a username-existence oracle; the attempted
		// user is logged server-side (matchRule's vlogf).
		return nil, c.errBanner(fmt.Sprintf("tailnet policy does not permit you to SSH as user %q", c.info.sshUser), nil)
	case rejected, noPolicy:
		return nil, c.errBanner("tailnet policy does not permit you to SSH to this node", fmt.Errorf("failed to evaluate policy, result: %s", result))
	default:
		return nil, c.errBanner("failed to evaluate tailnet policy", fmt.Errorf("failed to evaluate policy, result: %s", result))
	}

	c.action0 = action

	if action.Accept || action.HoldAndDelegate != "" {
		// Immediately look up user information for purposes of generating
		// hold and delegate URL (if necessary).
		lu, err := userLookup(localUser)
		if err != nil {
			// One fixed client-visible message for every lookup failure
			// cause; the underlying error is logged server-side only, so
			// the banner reveals nothing about local users beyond the name
			// the policy already mapped for this client.
			return nil, c.errBanner(fmt.Sprintf("failed to look up local user %q ", localUser), err)
		}
		gids, err := lu.GroupIds()
		if err != nil {
			return nil, c.errBanner("failed to look up local user's group IDs", err)
		}
		c.userGroupIDs = gids
		c.localUser = lu
		c.mappedLocalUser = localUser
		c.acceptEnv = acceptEnv
	}

	for {
		switch {
		case action.Accept:
			metricTerminalAccept.Add(1)
			if action.Message != "" {
				if err := c.spac.SendAuthBanner(action.Message); err != nil {
					return nil, c.errUnexpected(fmt.Errorf("error sending auth welcome message: %w", err))
				}
			}
			c.finalAction = action
			return &ssh.Permissions{}, nil
		case action.Reject:
			metricTerminalReject.Add(1)
			c.finalAction = action
			return nil, c.errDenied(action.Message)
		case action.HoldAndDelegate != "":
			if action.Message != "" {
				if err := c.spac.SendAuthBanner(action.Message); err != nil {
					return nil, c.errUnexpected(fmt.Errorf("error sending hold and delegate message: %w", err))
				}
			}

			url := action.HoldAndDelegate

			// Allow the delegate fetch to reach its own timeout before
			// login grace closes the transport. Keep the transport deadline
			// in case the fetch does not return on context cancellation.
			c.extendLoginGrace(holdDelegateGrace)

			// Connection teardown also cancels the delegate fetch.
			ctx := c.preAuthCtx
			if ctx == nil {
				ctx = context.Background()
			}

			metricHolds.Add(1)
			url = c.expandDelegateURLLocked(url)

			var err error
			action, err = c.fetchSSHAction(ctx, url)
			if err != nil {
				metricTerminalFetchError.Add(1)
				return nil, c.errBanner("failed to fetch next SSH action", fmt.Errorf("fetch failed from %s: %w", url, err))
			}
		default:
			metricTerminalMalformed.Add(1)
			return nil, c.errBanner("reached Action that had neither Accept, Reject, nor HoldAndDelegate", nil)
		}
	}
}

// ServerConfig implements gliderssh.ServerConfigCallback.
func (c *conn) ServerConfig(ctx gliderssh.Context) *ssh.ServerConfig {
	return &ssh.ServerConfig{
		AuthLogCallback: func(_ ssh.ConnMetadata, _ string, err error) {
			// x/crypto calls this with nil only after successful authentication.
			// Unsigned public-key queries do not reach this callback.
			if err == nil && !c.insecureSkipTailscaleAuth {
				c.mu.Lock()
				c.authCompleted.Store(true)
				c.stopLoginGraceLocked()
				c.mu.Unlock()
				// Cover policy changes during authentication and arm rule expiry.
				go func() {
					c.recheckPolicy()
					if c.authRecheckDone != nil {
						close(c.authRecheckDone)
					}
				}()
			}
		},
		PreAuthConnCallback: func(spac ssh.ServerPreAuthConn) {
			c.spac = spac
		},
		NoClientAuth: true, // required for the NoClientAuthCallback to run
		NoClientAuthCallback: func(cm ssh.ConnMetadata) (*ssh.Permissions, error) {
			// First perform client authentication, which can potentially
			// involve multiple steps (for example prompting user to log in to
			// Tailscale admin panel to confirm identity).
			perms, err := c.clientAuth(cm)
			if err != nil {
				return nil, err
			}

			// Authentication succeeded. Buggy SSH clients get confused by
			// success from the "none" auth method. As a workaround, let users
			// specify a username ending in "+password" to force password auth.
			// The actual value of the password doesn't matter.
			if strings.HasSuffix(cm.User(), forcePasswordSuffix) {
				return nil, &ssh.PartialSuccessError{
					Next: ssh.ServerAuthCallbacks{
						PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
							return &ssh.Permissions{}, nil
						},
					},
				}
			}

			return perms, nil
		},
		PasswordCallback: func(cm ssh.ConnMetadata, pword []byte) (*ssh.Permissions, error) {
			// Some clients don't request 'none' authentication. Instead, they
			// immediately supply a password. We humor them by accepting the
			// password, but authenticate as usual, ignoring the actual value of
			// the password.
			return c.clientAuth(cm)
		},
		PublicKeyCallback: func(cm ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Some clients don't request 'none' authentication. Instead, they
			// immediately supply a public key. We humor them by accepting the
			// key, but authenticate as usual, ignoring the actual content of
			// the key.
			return c.clientAuth(cm)
		},
	}
}

func (srv *server) newConn() (*conn, error) {
	srv.mu.Lock()
	if srv.shutdownCalled {
		srv.mu.Unlock()
		// Avoid constructing a connection after shutdown. registerConn
		// checks again before publishing the initialized connection.
		return nil, errors.New("server is shutting down")
	}
	srv.mu.Unlock()
	c := &conn{srv: srv}
	now := srv.now()
	c.connID = fmt.Sprintf("ssh-conn-%s-%02x", now.UTC().Format(tstime.BasicDateTTime), randBytes(5))
	streamLocalFwdHandler := &gliderssh.ForwardedUnixHandler{}
	c.Server = &gliderssh.Server{
		Version:              "Tailscale",
		ServerConfigCallback: c.ServerConfig,

		IdleTimeout: sshIdleTimeout(),

		Handler:                       c.handleSessionPostSSHAuth,
		LocalPortForwardingCallback:   c.mayForwardLocalPortTo,
		ReversePortForwardingCallback: c.mayReversePortForwardTo,

		LocalUnixForwardingCallback:   c.mayForwardLocalUnixTo,
		ReverseUnixForwardingCallback: c.mayReverseUnixForwardTo,

		SubsystemHandlers: map[string]gliderssh.SubsystemHandler{
			"sftp": c.handleSessionPostSSHAuth,
		},
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"direct-tcpip":                   gliderssh.DirectTCPIPHandler,
			"direct-streamlocal@openssh.com": gliderssh.DirectStreamLocalHandler,
		},
		RequestHandlers: map[string]gliderssh.RequestHandler{
			"streamlocal-forward@openssh.com":        streamLocalFwdHandler.HandleSSHRequest,
			"cancel-streamlocal-forward@openssh.com": streamLocalFwdHandler.HandleSSHRequest,
		},
	}
	ss := c.Server
	maps.Copy(ss.RequestHandlers, gliderssh.DefaultRequestHandlers)
	maps.Copy(ss.ChannelHandlers, gliderssh.DefaultChannelHandlers)
	maps.Copy(ss.SubsystemHandlers, gliderssh.DefaultSubsystemHandlers)
	c.wireForwarding(ss)
	keys, err := getHostKeys(srv.lb.TailscaleVarRoot(), srv.logf)
	if err != nil {
		return nil, err
	}
	for _, signer := range keys {
		ss.AddHostKey(signer)
	}
	return c, nil
}

// mayReversePortPortForwardTo reports whether the ctx should be allowed to port forward
// to the specified host and port.
// TODO(bradfitz/maisem): should we have more checks on host/port?
func (c *conn) mayReversePortForwardTo(ctx gliderssh.Context, destinationHost string, destinationPort uint32) bool {
	if sshDisableForwarding() || c.finalAction == nil || !c.finalAction.AllowRemotePortForwarding {
		return false
	}
	// The latched forwarding bit may be stale. See recheckPolicy.
	if !c.recheckForwardingPolicy() {
		return false
	}
	metricRemotePortForward.Add(1)
	return true
}

// mayForwardLocalPortTo reports whether the ctx should be allowed to port forward
// to the specified host and port.
// TODO(bradfitz/maisem): should we have more checks on host/port?
func (c *conn) mayForwardLocalPortTo(ctx gliderssh.Context, destinationHost string, destinationPort uint32) bool {
	if sshDisableForwarding() || c.finalAction == nil || !c.finalAction.AllowLocalPortForwarding {
		return false
	}
	// The latched forwarding bit may be stale. See recheckPolicy.
	if !c.recheckForwardingPolicy() {
		return false
	}
	metricLocalPortForward.Add(1)
	return true
}

// mayForwardLocalUnixTo is the server-side handler for
// direct-streamlocal@openssh.com (SSH -L with Unix sockets). It returns a
// connection to the specified Unix domain socket path if forwarding is
// permitted, or an error if not. On unix the dial goes through
// conn.fwdDialUnix.
func (c *conn) mayForwardLocalUnixTo(ctx gliderssh.Context, socketPath string) (net.Conn, error) {
	if sshDisableForwarding() || c.finalAction == nil || !c.finalAction.AllowLocalPortForwarding {
		return nil, gliderssh.ErrRejected
	}
	// The latched forwarding bit may be stale. See recheckPolicy.
	if !c.recheckForwardingPolicy() {
		return nil, gliderssh.ErrRejected
	}
	metricLocalPortForward.Add(1)
	return c.fwdDialUnix(ctx, socketPath)
}

// mayReverseUnixForwardTo is the server-side handler for
// streamlocal-forward@openssh.com (SSH -R with Unix sockets). It returns a
// listener for the specified Unix domain socket path if reverse forwarding
// is permitted, or an error if not. On unix the listener comes from
// conn.fwdListenUnix.
func (c *conn) mayReverseUnixForwardTo(ctx gliderssh.Context, socketPath string) (net.Listener, error) {
	if sshDisableForwarding() || c.finalAction == nil || !c.finalAction.AllowRemotePortForwarding {
		return nil, gliderssh.ErrRejected
	}
	// The latched forwarding bit may be stale. See recheckPolicy.
	if !c.recheckForwardingPolicy() {
		return nil, gliderssh.ErrRejected
	}
	metricRemotePortForward.Add(1)
	return c.fwdListenUnix(ctx, socketPath)
}

// sshPolicy returns the SSHPolicy for current node.
// If there is no SSHPolicy in the netmap, it returns a debugPolicy
// if one is defined.
func (c *conn) sshPolicy() (_ *tailcfg.SSHPolicy, ok bool) {
	lb := c.srv.lb
	if !lb.ShouldRunSSH() {
		return nil, false
	}
	nm := lb.NetMapNoPeers()
	if nm == nil {
		return nil, false
	}
	if pol := nm.SSHPolicy; pol != nil && !envknob.SSHIgnoreTailnetPolicy() {
		return pol, true
	}
	debugPolicyFile := envknob.SSHPolicyFile()
	if debugPolicyFile != "" {
		c.logf("reading debug SSH policy file: %v", debugPolicyFile)
		f, err := os.ReadFile(debugPolicyFile)
		if err != nil {
			c.logf("error reading debug SSH policy file: %v", err)
			return nil, false
		}
		p := new(tailcfg.SSHPolicy)
		if err := json.Unmarshal(f, p); err != nil {
			c.logf("invalid JSON in %v: %v", debugPolicyFile, err)
			return nil, false
		}
		return p, true
	}
	return nil, false
}

func toIPPort(a net.Addr) (ipp netip.AddrPort) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return
	}
	tanetaddr, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return
	}
	return netip.AddrPortFrom(tanetaddr.Unmap(), uint16(ta.Port))
}

// connInfo populates the sshConnInfo from the provided arguments,
// validating only that they represent a known Tailscale identity.
func (c *conn) setInfo(cm ssh.ConnMetadata) error {
	if c.info != nil {
		return nil
	}
	ci := &sshConnInfo{
		sshUser: strings.TrimSuffix(cm.User(), forcePasswordSuffix),
		src:     toIPPort(cm.RemoteAddr()),
		dst:     toIPPort(cm.LocalAddr()),
	}
	if !tsaddr.IsTailscaleIP(ci.dst.Addr()) {
		return fmt.Errorf("tailssh: rejecting non-Tailscale local address %v", ci.dst)
	}
	if !tsaddr.IsTailscaleIP(ci.src.Addr()) {
		return fmt.Errorf("tailssh: rejecting non-Tailscale remote address %v", ci.src)
	}
	node, uprof, ok := c.srv.lb.WhoIs("tcp", ci.src)
	if !ok {
		return fmt.Errorf("unknown Tailscale identity from src %v", ci.src)
	}
	ci.node = node
	ci.uprof = uprof

	c.idH = string(cm.SessionID())
	c.info = ci
	c.logf("handling conn: %v", ci.String())
	return nil
}

type evalResult string

const (
	noPolicy     evalResult = "no policy"
	rejected     evalResult = "rejected"
	rejectedUser evalResult = "rejected user"
	accepted     evalResult = "accept"
)

// evaluatePolicy returns the SSHAction, localUser, acceptEnv, and matched
// rule after evaluating the SSHPolicy for this conn. The rule is the
// netmap rule that produced the action, nil unless result is accepted.
// Callers use its RuleExpires to arm the conn-level expiry timer.
func (c *conn) evaluatePolicy() (*tailcfg.SSHAction, string, []string, *tailcfg.SSHRule, evalResult) {
	return c.evaluatePolicyWithUserLookup(userLookup)
}

func (c *conn) evaluatePolicyWithUserLookup(lookup func(string) (*userMeta, error)) (_ *tailcfg.SSHAction, localUser string, acceptEnv []string, rule *tailcfg.SSHRule, result evalResult) {
	pol, ok := c.sshPolicy()
	if !ok {
		return nil, "", nil, nil, noPolicy
	}
	return c.evalSSHPolicyWithUserLookup(pol, lookup)
}

// handleSessionPostSSHAuth runs an SSH session after the SSH-level authentication,
// but not necessarily before all the Tailscale-level extra verification has
// completed. It also handles SFTP requests.
func (c *conn) handleSessionPostSSHAuth(s gliderssh.Session) {
	// Re-evaluate the policy before honoring a new session channel. The
	// conn's latched finalAction, covering localUser, recorders, duration,
	// and the env allowlist, may be stale if the policy changed since
	// auth. A material change closes the connection, and the session
	// exits 255 before running anything.
	if material, why, _ := c.materialPolicyChange(); material {
		fmt.Fprintf(s.Stderr(), "tailscale: access revoked\r\n")
		// 255 is an SSH-layer failure. No user command ever ran. See
		// run()'s attachSession branch, which uses the same exit code.
		s.Exit(255)
		c.revokeConn(why)
		return
	}

	// Do this check after auth, but before starting the session.
	switch s.Subsystem() {
	case "sftp":
		if sshDisableSFTP() {
			fmt.Fprintf(s.Stderr(), "sftp disabled\r\n")
			s.Exit(1)
			return
		}
		metricSFTP.Add(1)
	case "":
		// Regular SSH session.
	default:
		fmt.Fprintf(s.Stderr(), "Unsupported subsystem %q\r\n", s.Subsystem())
		s.Exit(1)
		return
	}

	ss := c.newSSHSession(s)
	ss.logf("handling new SSH connection from %v (%v) to ssh-user %q", c.info.uprof.LoginName, c.info.src.Addr(), c.localUser.Username)
	ss.logf("access granted to %v as ssh-user %q", c.info.uprof.LoginName, c.localUser.Username)

	if f, ok := hookSSHLoginSuccess.GetOk(); ok {
		f(c.srv.logf, c)
	}

	ss.run()
}

func (c *conn) expandDelegateURLLocked(actionURL string) string {
	nm := c.srv.lb.NetMapNoPeers()
	ci := c.info
	lu := c.localUser
	var dstNodeID string
	if nm != nil {
		dstNodeID = fmt.Sprint(int64(nm.SelfNode.ID()))
	}
	return strings.NewReplacer(
		"$SRC_NODE_IP", url.QueryEscape(ci.src.Addr().String()),
		"$SRC_NODE_ID", fmt.Sprint(int64(ci.node.ID())),
		"$DST_NODE_IP", url.QueryEscape(ci.dst.Addr().String()),
		"$DST_NODE_ID", dstNodeID,
		"$SSH_USER", url.QueryEscape(ci.sshUser),
		"$LOCAL_USER", url.QueryEscape(lu.Username),
	).Replace(actionURL)
}

// sshSession is an accepted Tailscale SSH session.
type sshSession struct {
	gliderssh.Session
	sharedID string // ID that's shared with control
	logf     logger.Logf

	ctx           context.Context
	cancelCtx     context.CancelCauseFunc
	conn          *conn
	agentListener net.Listener // non-nil if agent-forwarding requested+allowed

	// initialized by launchProcess:
	osSessionState // the process itself; see process_*.go
	wrStdin        io.WriteCloser
	rdStdout       io.ReadCloser
	rdStderr       io.ReadCloser  // rdStderr is nil for pty sessions
	ptyReq         *gliderssh.Pty // non-nil for pty sessions

	// childPipes is a list of pipes that need to be closed when the process exits.
	// For pty sessions, this is the tty fd.
	// For non-pty sessions, this is the stdin, stdout, stderr fds.
	childPipes []io.Closer

	// We use this sync.Once to ensure that we only terminate the process once,
	// either it exits itself or is terminated
	exitOnce sync.Once

	// exitHandled is closed when killProcessOnContextDone finishes writing any
	// termination message to the client. run() waits on this before calling
	// ss.Exit to ensure the message is flushed before the SSH channel is torn
	// down. It is initialized by run() before starting killProcessOnContextDone.
	exitHandled chan struct{}
}

func (ss *sshSession) vlogf(format string, args ...any) {
	if sshVerboseLogging() {
		ss.logf(format, args...)
	}
}

func (c *conn) newSSHSession(s gliderssh.Session) *sshSession {
	sharedID := fmt.Sprintf("sess-%s-%02x", c.srv.now().UTC().Format(tstime.BasicDateTTime), randBytes(5))
	c.logf("starting session: %v", sharedID)
	ctx, cancel := context.WithCancelCause(s.Context())
	return &sshSession{
		Session:   s,
		sharedID:  sharedID,
		ctx:       ctx,
		cancelCtx: cancel,
		conn:      c,
		logf:      logger.WithPrefix(c.srv.logf, "ssh-session("+sharedID+"): "),
	}
}

const (
	// delegateFetchTimeout bounds one delegated action fetch, including retries.
	delegateFetchTimeout = 30 * time.Minute

	// holdDelegateGrace is the login-grace period while fetching a delegated
	// action. It allows the fetch to time out before closing the transport.
	holdDelegateGrace = delegateFetchTimeout + 5*time.Minute
)

// armLoginGrace arms the pre-auth login-grace timer; on expiry the
// connection is closed at the raw socket. The timer is stopped at auth
// completion by stopLoginGraceLocked in AuthLogCallback,
// and extended while a HoldAndDelegate approval is in flight by
// extendLoginGrace. Superseded timers are disarmed by the self-identity
// check under mu.
func (c *conn) armLoginGrace() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armLoginGraceLocked(loginGraceTime())
}

func (c *conn) armLoginGraceLocked(d time.Duration) {
	var t *time.Timer
	t = time.AfterFunc(d, func() {
		c.mu.Lock()
		if c.authCompleted.Load() || c.graceTimer != t {
			// Auth already completed, or this timer was stopped or
			// superseded by a later re-arm.
			c.mu.Unlock()
			return
		}
		c.graceTimer = nil
		c.mu.Unlock()
		c.logf("ssh: login grace period expired before authentication completed; closing connection")
		c.closeConn()
	})
	c.graceTimer = t
}

// stopLoginGraceLocked stops the login-grace timer once auth has
// completed. The caller holds c.mu.
func (c *conn) stopLoginGraceLocked() {
	if c.graceTimer != nil {
		c.graceTimer.Stop()
		c.graceTimer = nil
	}
}

// extendLoginGrace re-arms the login-grace timer to d from now.
func (c *conn) extendLoginGrace(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLoginGraceLocked()
	c.armLoginGraceLocked(d)
}

// armRuleExpiryLocked arms the conn-level RuleExpires timer, which fires
// at expiry and re-evaluates the policy; an expired rule fails closed in
// matchRule. The timer is armed at auth completion and re-armed on every
// non-material re-evaluation by recheckPolicy. The caller holds c.mu.
func (c *conn) armRuleExpiryLocked(r *tailcfg.SSHRule) {
	if c.ruleTimer != nil {
		// Re-arming happens when recheckPolicy's non-material
		// re-evaluation matched a differently-expiring rule. A superseded
		// one-shot timer is stopped rather than left to fire its own
		// extra recheck later.
		c.ruleTimer.Stop()
		c.ruleTimer = nil
	}
	if r == nil || r.RuleExpires == nil {
		return
	}
	d := r.RuleExpires.Sub(c.srv.now())
	if d < 0 {
		d = 0
	}
	c.ruleTimer = time.AfterFunc(d, func() { go c.recheckPolicy() })
}

// stopConnTimers stops the login-grace and RuleExpires timers at conn
// teardown. It also latches teardownDone, so any later non-material
// recheck must not re-arm ruleTimer. See the field's comment.
func (c *conn) stopConnTimers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.teardownDone = true
	if c.graceTimer != nil {
		c.graceTimer.Stop()
		c.graceTimer = nil
	}
	if c.ruleTimer != nil {
		c.ruleTimer.Stop()
		c.ruleTimer = nil
	}
}

// closeConn cancels authentication and closes both the raw transport and
// gliderssh connections. It is safe to call concurrently and more than once.
func (c *conn) closeConn() {
	c.closeOnce.Do(func() {
		if c.preAuthCancel != nil {
			c.preAuthCancel()
		}
		if c.netConn != nil {
			c.netConn.Close()
		}
		if c.Server != nil {
			c.Server.Close()
		}
	})
}

// revokeConn cancels each session with an "Access revoked." message and
// closes the connection. This is triggered when a policy change invalidates
// its grant.
func (c *conn) revokeConn(reason string) {
	metricPolicyChangeKick.Add(1)
	c.logf("session no longer valid per new SSH policy (%v); closing connection", reason)
	c.mu.Lock()
	for _, s := range c.sessions {
		s.cancelCtx(userVisibleError{
			fmt.Sprintf("Access revoked.\r\n"),
			context.Canceled,
		})
	}
	c.mu.Unlock()
	c.closeConn()
}

// recheckPolicy re-evaluates the current SSHPolicy against what the conn
// latched at auth time and reports whether the conn still holds its grant.
// On a material change, either revocation or narrowing, it revokes the
// connection and returns false; see materialPolicyChange. It costs a
// local netmap policy scan plus, only when the mapped username is
// unchanged, a userLookup to verify account identity.
func (c *conn) recheckPolicy() bool {
	return c.recheckPolicyWithUserLookup(userLookup)
}

// recheckForwardingPolicy checks policy without forking an account lookup for
// each forwarded connection (e.g. every request through SSH -D). Account
// identity is checked at authentication, policy updates, rule expiry, and
// session gates.
func (c *conn) recheckForwardingPolicy() bool {
	return c.recheckPolicyWithUserLookup(func(string) (*userMeta, error) {
		return c.localUser, nil
	})
}

func (c *conn) recheckPolicyWithUserLookup(lookup func(string) (*userMeta, error)) bool {
	c.recheckMu.Lock()
	defer c.recheckMu.Unlock()
	material, why, rule := c.materialPolicyChangeWithUserLookup(lookup)
	if !material {
		// Keep the conn-level RuleExpires timer in step with the rule
		// that currently matches: a non-material re-evaluation, from a
		// policy edit or kick, can land on a different rule whose expiry
		// is later, earlier, or absent. Do not re-arm past the conn's
		// teardown; see teardownDone.
		c.mu.Lock()
		if !c.teardownDone {
			c.armRuleExpiryLocked(rule)
		}
		c.mu.Unlock()
		return true
	}
	c.revokeConn(why)
	return false
}

// materialPolicyChange reports whether the current policy revokes or narrows
// the authenticated grant, or changes its recording requirements.
func (c *conn) materialPolicyChange() (material bool, why string, rule *tailcfg.SSHRule) {
	return c.materialPolicyChangeWithUserLookup(userLookup)
}

// materialPolicyChangeWithUserLookup re-evaluates the grant using lookup for
// account identity, including the non-root check for "=" mappings.
func (c *conn) materialPolicyChangeWithUserLookup(lookup func(string) (*userMeta, error)) (material bool, why string, rule *tailcfg.SSHRule) {
	// Resolve each name only once, including the lookup required by "=".
	// An inconclusive lookup may retain the authenticated identity only for
	// the same policy spelling; it cannot authorize a remapping or root.
	type lookupResult struct {
		u   *userMeta
		err error
	}
	lookups := map[string]lookupResult{}
	cachedLookup := func(name string) (*userMeta, error) {
		r, ok := lookups[name]
		if !ok {
			r.u, r.err = lookup(name)
			lookups[name] = r
		}
		return r.u, r.err
	}
	a, localUser, freshAcceptEnv, rule, result := c.evaluatePolicyWithUserLookup(func(name string) (*userMeta, error) {
		u, err := cachedLookup(name)
		if err != nil && !isUserMissing(err) && name == c.mappedLocalUser {
			return c.localUser, nil
		}
		return u, err
	})
	c.vlogf("recheck: %+v %v %v", a, localUser, result)
	if result != accepted {
		return true, fmt.Sprintf("policy evaluation result: %v", result), nil
	}
	if a == nil {
		return true, "policy returned a nil action", nil
	}
	if a.Reject {
		return true, "rule changed from Accept to Reject", nil
	}
	if a.Accept && a.HoldAndDelegate != "" {
		return true, "malformed action: both Accept and HoldAndDelegate", nil
	}
	if !a.Accept && a.HoldAndDelegate == "" {
		return true, "malformed action: neither Accept, Reject, nor HoldAndDelegate", nil
	}
	// Compare the policy spelling before lookup: aliases and numeric UIDs
	// can resolve to a different canonical username without a policy change.
	if localUser != c.mappedLocalUser {
		return true, fmt.Sprintf("local user changed from %q to %q", c.mappedLocalUser, localUser), nil
	}
	// Re-resolve the account to detect deletion or UID/primary GID changes. A lookup
	// outage leaves identity unchanged, but must not skip policy checks.
	lu, err := cachedLookup(localUser)
	if err != nil {
		if isUserMissing(err) {
			return true, fmt.Sprintf("local user %q no longer exists", localUser), nil
		}
		c.logf("ssh: policy recheck: local user %q lookup failed (%v); retaining identity and checking remaining policy", localUser, err)
	} else if lu.Uid != c.localUser.Uid || lu.Gid != c.localUser.Gid || lu.Username != c.localUser.Username {
		return true, fmt.Sprintf("local user %q identity changed from %s (uid %s, gid %s) to %s (uid %s, gid %s)", localUser, c.localUser.Username, c.localUser.Uid, c.localUser.Gid, lu.Username, lu.Uid, lu.Gid), nil
	}
	old := c.finalAction
	if old == nil || c.action0 == nil {
		return true, "conn has no latched action", nil
	}
	if acceptEnvNarrowed(c.acceptEnv, freshAcceptEnv) {
		return true, "accept-env pattern removed", nil
	}
	oldRecorders, oldFailure := recordingConfig(c.action0, old)
	freshRecorders, freshFailure := recordingConfig(a, a)
	if !a.Accept {
		if c.action0.Accept {
			return true, "rule changed from Accept to HoldAndDelegate", nil
		}
		// Keep the delegated grant, but compare any recording requirements
		// inherited from the hold rule as well as its AcceptEnv above.
		freshRecorders, freshFailure = recordingConfig(a, old)
	}
	if recordersChanged(oldRecorders, freshRecorders) {
		return true, "session recording obligation changed", nil
	}
	if recFailureChanged(oldFailure, freshFailure) {
		return true, "recording-failure policy changed", nil
	}
	if !a.Accept {
		return false, "", rule
	}
	if old.AllowLocalPortForwarding && !a.AllowLocalPortForwarding {
		return true, "local port forwarding revoked", nil
	}
	if old.AllowRemotePortForwarding && !a.AllowRemotePortForwarding {
		return true, "remote port forwarding revoked", nil
	}
	if old.AllowAgentForwarding && !a.AllowAgentForwarding {
		return true, "agent forwarding revoked", nil
	}
	if durShorter(a.SessionDuration, old.SessionDuration) {
		return true, fmt.Sprintf("session duration cap shortened from %v to %v", old.SessionDuration, a.SessionDuration), nil
	}
	return false, "", rule
}

// recordersChanged compares recorder lists without regard to order, but with
// duplicate counts preserved. Changes in either direction require
// reauthentication because recording state is fixed at authentication.
func recordersChanged(old, fresh []netip.AddrPort) bool {
	if len(old) != len(fresh) {
		return true
	}
	counts := make(map[netip.AddrPort]int, len(old))
	for _, r := range old {
		counts[r]++
	}
	for _, r := range fresh {
		if counts[r] == 0 {
			return true
		}
		counts[r]--
	}
	return false
}

// isUserMissing recognizes an absent account, not an unavailable lookup source.
// NSS can report "not found" (getent exit 2) during a directory outage;
// userLookup cannot distinguish that case from deletion.
func isUserMissing(err error) bool {
	_, nameMissing := errors.AsType[stduser.UnknownUserError](err)
	_, uidMissing := errors.AsType[stduser.UnknownUserIdError](err)
	return nameMissing || uidMissing
}

// recFailureChanged compares failure requirements in both directions, including
// messages and notification destinations. Nil is equivalent to an empty action.
func recFailureChanged(old, fresh *tailcfg.SSHRecorderFailureAction) bool {
	var o, f tailcfg.SSHRecorderFailureAction
	if old != nil {
		o = *old
	}
	if fresh != nil {
		f = *fresh
	}
	return o != f
}

// durShorter reports whether fresh is a shorter cap than old. Zero means
// uncapped, the maximum. A longer or removed cap is an extension.
func durShorter(fresh, old time.Duration) bool {
	if fresh == 0 {
		return false
	}
	if old == 0 {
		return true
	}
	return fresh < old
}

// acceptEnvNarrowed reports whether the fresh accept-env patterns
// accept strictly less than the latched ones. Literal latched patterns
// are checked against the fresh patterns with matchAcceptEnvPattern, so
// a widening rewrite such as FOO_1 to FOO_* is an extension. A wildcard
// latched pattern not present verbatim is conservatively treated as a
// removal.
func acceptEnvNarrowed(old, fresh []string) bool {
	for _, o := range old {
		if slices.Contains(fresh, o) {
			continue
		}
		if o == "*" || strings.ContainsAny(o, "*?") {
			return true
		}
		covered := false
		for _, f := range fresh {
			if matchAcceptEnvPattern(f, o) {
				covered = true
				break
			}
		}
		if !covered {
			return true
		}
	}
	return false
}

func (c *conn) fetchSSHAction(ctx context.Context, url string) (*tailcfg.SSHAction, error) {
	ctx, cancel := context.WithTimeout(ctx, delegateFetchTimeout)
	defer cancel()
	bo := backoff.NewBackoff("fetch-ssh-action", c.logf, 10*time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		res, err := c.srv.lb.DoNoiseRequest(req)
		if err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		if res.StatusCode != 200 {
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if len(body) > 1<<10 {
				body = body[:1<<10]
			}
			c.logf("fetch of %v: %s, %s", url, res.Status, body)
			bo.BackOff(ctx, fmt.Errorf("unexpected status: %v", res.Status))
			continue
		}
		a := new(tailcfg.SSHAction)
		err = json.NewDecoder(res.Body).Decode(a)
		res.Body.Close()
		if err != nil {
			c.logf("invalid next SSHAction JSON from %v: %v", url, err)
			bo.BackOff(ctx, err)
			continue
		}
		return a, nil
	}
}

// killProcessOnContextDone waits for ss.ctx to be done and kills the process,
// unless the process has already exited.
func (ss *sshSession) killProcessOnContextDone() {
	defer close(ss.exitHandled)
	<-ss.ctx.Done()
	// Either the process has already exited, in which case this does nothing.
	// Or, the process is still running in which case this will kill it.
	ss.exitOnce.Do(func() {
		err := context.Cause(ss.ctx)
		if serr, ok := err.(SSHTerminationError); ok {
			msg := serr.SSHTerminationMessage()
			if msg != "" {
				io.WriteString(ss.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
			}
		}
		ss.logf("terminating SSH session from %v: %v", ss.conn.info.src.Addr(), err)
		// We don't need to wait for the process here, sshSession.run()
		// does the waiting regardless of termination reason.
		ss.hangupProcess()
	})
}

// isNotFoundOrExecutable reports whether err is a launchProcess
// failure caused by the command not existing on disk.
func isNotFoundOrExecutable(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

// attachSession registers ss as an active session.
func (c *conn) attachSession(ss *sshSession) {
	c.srv.sessionWaitGroup.Add(1)
	if ss.sharedID == "" {
		panic("empty sharedID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = append(c.sessions, ss)
}

// detachSession unregisters s from the list of active sessions.
func (c *conn) detachSession(ss *sshSession) {
	defer c.srv.sessionWaitGroup.Done()
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, s := range c.sessions {
		if s == ss {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			break
		}
	}
}

var errSessionDone = errors.New("session is done")

// run is the entrypoint for a newly accepted SSH session.
//
// It handles ss once it's been accepted and determined
// that it should run.
func (ss *sshSession) run() {
	metricActiveSessions.Add(1)
	defer metricActiveSessions.Add(-1)
	defer ss.cancelCtx(errSessionDone)
	defer ss.Close() // CHANNEL_CLOSE, last on the wire; see ss.Exit below.

	if attached := ss.conn.srv.attachSessionToConnIfNotShutdown(ss); !attached {
		fmt.Fprintf(ss, "Tailscale SSH is shutting down\r\n")
		// Use 255 for server failures before the command starts, following
		// the ssh(1) convention for SSH errors.
		ss.Exit(255)
		return
	}
	defer ss.conn.detachSession(ss)

	lu := ss.conn.localUser
	logf := ss.logf

	if ss.conn.finalAction.SessionDuration != 0 {
		t := time.AfterFunc(ss.conn.finalAction.SessionDuration, func() {
			ss.cancelCtx(userVisibleError{
				fmt.Sprintf("Session timeout of %v elapsed.", ss.conn.finalAction.SessionDuration),
				context.DeadlineExceeded,
			})
		})
		defer t.Stop()
	}

	if err := canSwitchToLocalUser(lu); err != nil {
		ss.logf("%v", err)
		fmt.Fprintf(ss, "can't switch user\r\n")
		// The server could not start the command.
		ss.Exit(255)
		return
	}

	// Take control of the PTY so that we can configure it below.
	// See https://github.com/tailscale/tailscale/issues/4146
	ss.DisablePTYEmulation()

	if ss.Subsystem() != "sftp" {
		if err := ss.handleSSHAgentForwarding(ss, lu); err != nil {
			ss.logf("agent forwarding failed: %v", err)
		} else if ss.agentListener != nil {
			// TODO(maisem/bradfitz): add a way to close all session resources
			defer ss.closeAgentForwarding()
		}
	}

	// Recording policy also applies to SFTP sessions, including scp -s.
	// These record session metadata rather than the binary protocol; see
	// recording.metadataOnly.
	var rec *recording // or nil if disabled
	if ss.shouldRecord() {
		var err error
		rec, err = ss.startNewRecording()
		if err != nil {
			// SFTP stdout is a binary protocol stream; report rejection on
			// stderr without changing shell-session output behavior.
			out := io.Writer(ss)
			if ss.Subsystem() == "sftp" {
				out = ss.Stderr()
			}
			if uve, ok := errors.AsType[userVisibleError](err); ok {
				fmt.Fprintf(out, "%s\r\n", uve.SSHTerminationMessage())
			} else {
				fmt.Fprintf(out, "can't start new recording\r\n")
			}
			ss.logf("startNewRecording: %v", err)
			// Exit 254 indicates that recording policy prevented session startup.
			ss.Exit(254)
			return
		}
		ss.logf("startNewRecording: <nil>")
		if rec != nil {
			defer rec.Close()
		}
	}

	err := ss.launchProcess()
	if err != nil {
		logf("start failed: %v", err.Error())
		exitCode := 1
		if errors.Is(err, context.Canceled) {
			cause := context.Cause(ss.ctx)
			if serr, ok := cause.(SSHTerminationError); ok {
				if msg := serr.SSHTerminationMessage(); msg != "" {
					io.WriteString(ss.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
				}
			}
		} else if isNotFoundOrExecutable(err) {
			// Use the POSIX shell convention for a missing command:
			// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08_02
			exitCode = 127
		}
		ss.Exit(exitCode)
		return
	}
	ss.exitHandled = make(chan struct{})
	go ss.killProcessOnContextDone()

	// Wait for both output streams before sending CHANNEL_EOF.
	// Do not wait for stdin: clients may keep it open until CHANNEL_CLOSE.
	// The deferred ss.Close unblocks the stdin copier.
	var wg sync.WaitGroup

	go func() {
		defer ss.wrStdin.Close()
		if _, err := io.Copy(rec.writer("i", ss.wrStdin), ss); err != nil {
			logf("stdin copy: %v", err)
			ss.cancelCtx(err)
		}
	}()

	wg.Go(func() {
		defer ss.rdStdout.Close()
		if _, err := io.Copy(rec.writer("o", ss), ss.rdStdout); err != nil && !errors.Is(err, io.EOF) {
			logf("stdout copy: %v", err)
		}
	})

	// rdStderr is nil for ptys.
	if ss.rdStderr != nil {
		wg.Go(func() {
			defer ss.rdStderr.Close()
			// The asciinema format has no separate stderr channel. Record
			// stderr as output, as for PTY sessions.
			if _, err := io.Copy(rec.writer("o", ss.Stderr()), ss.rdStderr); err != nil {
				logf("stderr copy: %v", err)
			}
		})
	}

	exitCode, err := ss.waitProcess()

	if ss.ctx.Err() != nil {
		// Cancellation (e.g. recording upload failure) wrote a
		// termination message via killProcessOnContextDone; wait
		// for it before Exit closes the channel for writes.
		<-ss.exitHandled
	}

	// This will either make the SSH Termination goroutine be a no-op,
	// or itself will be a no-op because the process was killed by the
	// aforementioned goroutine.
	ss.exitOnce.Do(func() {})

	switch {
	case err != nil:
		ss.logf("Wait: %v", err)
		exitCode = 1
	case exitCode == 0:
		ss.logf("Session complete")
	default:
		ss.logf("Wait: code=%v", exitCode)
	}

	// Order on the wire: exit-status, remaining output, EOF,
	// CHANNEL_CLOSE (deferred ss.Close). RFC 4254 §6.10. CloseWrite
	// (CHANNEL_EOF) must wait for both output copiers: a write on
	// either stream after EOF fails and silently truncates that
	// stream's tail.
	ss.Exit(exitCode)
	closeAll(ss.childPipes...)
	wg.Wait()
	ss.CloseWrite()
}

// recordSSHToLocalDisk is a deprecated dev knob to allow recording SSH sessions
// to local storage. It is only used if there is no recording configured by the
// coordination server. This will be removed in the future.
var recordSSHToLocalDisk = envknob.RegisterBool("TS_DEBUG_LOG_SSH")

// recorders returns the list of recorders to use for this session.
// If the final action has a non-empty list of recorders, that list is
// returned. Otherwise, the list of recorders from the initial action
// is returned.
func (ss *sshSession) recorders() ([]netip.AddrPort, *tailcfg.SSHRecorderFailureAction) {
	return recordingConfig(ss.conn.action0, ss.conn.finalAction)
}

// recordingConfig applies the delegated action's recorder override, if present.
func recordingConfig(initial, final *tailcfg.SSHAction) ([]netip.AddrPort, *tailcfg.SSHRecorderFailureAction) {
	if len(final.Recorders) > 0 {
		return final.Recorders, final.OnRecordingFailure
	}
	return initial.Recorders, initial.OnRecordingFailure
}

func (ss *sshSession) shouldRecord() bool {
	recs, _ := ss.recorders()
	return len(recs) > 0 || recordSSHToLocalDisk()
}

type sshConnInfo struct {
	// sshUser is the requested local SSH username ("root", "alice", etc).
	sshUser string

	// src is the Tailscale IP and port that the connection came from.
	src netip.AddrPort

	// dst is the Tailscale IP and port that the connection came for.
	dst netip.AddrPort

	// node is srcIP's node.
	node tailcfg.NodeView

	// uprof is node's UserProfile.
	uprof tailcfg.UserProfile
}

func (ci *sshConnInfo) String() string {
	return fmt.Sprintf("%v->%v@%v", ci.src, ci.sshUser, ci.dst)
}

func (c *conn) ruleExpired(r *tailcfg.SSHRule) bool {
	if r.RuleExpires == nil {
		return false
	}
	return r.RuleExpires.Before(c.srv.now())
}

func (c *conn) evalSSHPolicy(pol *tailcfg.SSHPolicy) (*tailcfg.SSHAction, string, []string, *tailcfg.SSHRule, evalResult) {
	return c.evalSSHPolicyWithUserLookup(pol, userLookup)
}

func (c *conn) evalSSHPolicyWithUserLookup(pol *tailcfg.SSHPolicy, lookup func(string) (*userMeta, error)) (a *tailcfg.SSHAction, localUser string, acceptEnv []string, rule *tailcfg.SSHRule, result evalResult) {
	failedOnUser := false
	for _, r := range pol.Rules {
		if a, localUser, acceptEnv, err := c.matchRuleWithUserLookup(r, lookup); err == nil {
			return a, localUser, acceptEnv, r, accepted
		} else if errors.Is(err, errUserMatch) {
			failedOnUser = true
		}
	}
	result = rejected
	if failedOnUser {
		result = rejectedUser
	}
	return nil, "", nil, nil, result
}

// internal errors for testing; they don't escape to callers or logs.
var (
	errNilRule        = errors.New("nil rule")
	errNilAction      = errors.New("nil action")
	errRuleExpired    = errors.New("rule expired")
	errPrincipalMatch = errors.New("principal didn't match")
	errUserMatch      = errors.New("user didn't match")
	errInvalidConn    = errors.New("invalid connection state")
)

func (c *conn) matchRule(r *tailcfg.SSHRule) (*tailcfg.SSHAction, string, []string, error) {
	return c.matchRuleWithUserLookup(r, userLookup)
}

func (c *conn) matchRuleWithUserLookup(r *tailcfg.SSHRule, lookup func(string) (*userMeta, error)) (a *tailcfg.SSHAction, localUser string, acceptEnv []string, err error) {
	defer func() {
		c.vlogf("matchRule(%+v): %v", r, err)
	}()

	if c == nil {
		return nil, "", nil, errInvalidConn
	}
	if c.info == nil {
		c.logf("invalid connection state")
		return nil, "", nil, errInvalidConn
	}
	if r == nil {
		return nil, "", nil, errNilRule
	}
	if r.Action == nil {
		return nil, "", nil, errNilAction
	}
	if c.ruleExpired(r) {
		return nil, "", nil, errRuleExpired
	}
	if !c.anyPrincipalMatches(r.Principals) {
		return nil, "", nil, errPrincipalMatch
	}
	if !r.Action.Reject {
		// For all but Reject rules, SSHUsers is required.
		// If SSHUsers is nil or empty, mapLocalUser will return an
		// empty string anyway.
		localUser = mapLocalUser(r.SSHUsers, c.info.sshUser, lookup)
		if localUser == "" {
			return nil, "", nil, errUserMatch
		}
	}
	return r.Action, localUser, r.AcceptEnv, nil
}

func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string, lookup func(string) (*userMeta, error)) (localUser string) {
	v, ok := ruleSSHUsers[reqSSHUser]
	if !ok {
		v = ruleSSHUsers["*"]
	}
	if v == "=" {
		// Skip lookup for gokrazy as we intentionally fall back to a synthesized
		// root user there when user lookup fails.
		if distro.Get() == distro.Gokrazy {
			return reqSSHUser
		}

		// Immediately look up user information for purposes of generating
		// hold and delegate URL (if necessary).
		lu, err := lookup(reqSSHUser)
		if err != nil {
			return ""
		}
		// Don't match as root for autogroup:nonroot
		if isRootUser(lu) {
			return ""
		}
		return reqSSHUser
	}
	return v
}

func (c *conn) anyPrincipalMatches(ps []*tailcfg.SSHPrincipal) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if c.principalMatchesTailscaleIdentity(p) {
			return true
		}
	}
	return false
}

// principalMatchesTailscaleIdentity reports whether one of p's four fields
// that match the Tailscale identity match (Node, NodeIP, UserLogin, Any).
func (c *conn) principalMatchesTailscaleIdentity(p *tailcfg.SSHPrincipal) bool {
	ci := c.info
	if p.Any {
		return true
	}
	if !p.Node.IsZero() && ci.node.Valid() && p.Node == ci.node.StableID() {
		return true
	}
	if p.NodeIP != "" {
		if ip, _ := netip.ParseAddr(p.NodeIP); ip == ci.src.Addr() {
			return true
		}
	}
	if p.UserLogin != "" && ci.uprof.LoginName == p.UserLogin {
		return true
	}
	return false
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func (ss *sshSession) openFileForRecording(now time.Time) (_ io.WriteCloser, err error) {
	varRoot := ss.conn.srv.lb.TailscaleVarRoot()
	if varRoot == "" {
		return nil, errors.New("no var root for recording storage")
	}
	dir := filepath.Join(varRoot, "ssh-sessions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, fmt.Sprintf("ssh-session-%v-*.cast", now.UnixNano()))
	if err != nil {
		return nil, err
	}
	return f, nil
}

// startNewRecording starts a new SSH session recording.
// It may return a nil recording if recording is not available.
func (ss *sshSession) startNewRecording() (_ *recording, err error) {
	// We store the node key as soon as possible when creating
	// a new recording incase of FUS.
	nodeKey := ss.conn.srv.lb.NodeKey()
	if nodeKey.IsZero() {
		return nil, errors.New("ssh server is unavailable: no node key")
	}

	recorders, onFailure := ss.recorders()
	var localRecording bool
	if len(recorders) == 0 {
		if recordSSHToLocalDisk() {
			localRecording = true
		} else {
			return nil, errors.New("no recorders configured")
		}
	}

	var w gliderssh.Window
	if ptyReq, _, isPtyReq := ss.Pty(); isPtyReq {
		w = ptyReq.Window
	}

	term := envValFromList(ss.Environ(), "TERM")
	if term == "" {
		term = "xterm-256color" // something non-empty
	}

	now := time.Now()
	rec := &recording{
		ss:       ss,
		start:    now,
		failOpen: onFailure == nil || onFailure.TerminateSessionWithMessage == "",
		// Subsystem sessions (sftp) record metadata only; see the
		// recording.metadataOnly doc comment.
		metadataOnly: ss.Subsystem() != "",
	}

	// We want to use a background context for uploading and not ss.ctx.
	// ss.ctx is closed when the session closes, but we don't want to break the upload at that time.
	// Instead we want to wait for the session to close the writer when it finishes.
	ctx := context.Background()
	if localRecording {
		rec.out, err = ss.openFileForRecording(now)
		if err != nil {
			return nil, err
		}
	} else {
		var errChan <-chan error
		var attempts []*tailcfg.SSHRecordingAttempt
		rec.out, attempts, errChan, err = sessionrecording.ConnectToRecorder(ctx, recorders, ss.conn.srv.lb.Dialer().UserDial)
		if err != nil {
			if onFailure != nil && onFailure.NotifyURL != "" && len(attempts) > 0 {
				eventType := tailcfg.SSHSessionRecordingFailed
				if onFailure.RejectSessionWithMessage != "" {
					eventType = tailcfg.SSHSessionRecordingRejected
				}
				ss.notifyControl(ctx, nodeKey, eventType, attempts, onFailure.NotifyURL)
			}

			if onFailure != nil && onFailure.RejectSessionWithMessage != "" {
				ss.logf("recording: error starting recording (rejecting session): %v", err)
				return nil, userVisibleError{
					error: err,
					msg:   onFailure.RejectSessionWithMessage,
				}
			}
			ss.logf("recording: error starting recording (failing open): %v", err)
			return nil, nil
		}
		go func() {
			err := <-errChan
			if err == nil {
				select {
				case <-ss.ctx.Done():
					// Success.
					ss.logf("recording: finished uploading recording")
					return
				default:
					err = errors.New("recording upload ended before the SSH session")
				}
			}
			terminate := onFailure != nil && onFailure.TerminateSessionWithMessage != ""
			if terminate {
				ss.logf("recording: error uploading recording (closing session): %v", err)
				ss.cancelCtx(userVisibleError{
					error: err,
					msg:   onFailure.TerminateSessionWithMessage,
				})
			}
			if onFailure != nil && onFailure.NotifyURL != "" && len(attempts) > 0 {
				lastAttempt := attempts[len(attempts)-1]
				lastAttempt.FailureMessage = err.Error()

				eventType := tailcfg.SSHSessionRecordingFailed
				if terminate {
					eventType = tailcfg.SSHSessionRecordingTerminated
				}

				ss.notifyControl(ctx, nodeKey, eventType, attempts, onFailure.NotifyURL)
			}
			if terminate {
				return
			}
			ss.logf("recording: error uploading recording (failing open): %v", err)
		}()
	}

	// The requested subsystem (e.g. "sftp"), or "" for interactive
	// sessions. Subsystem requests carry no command string on the wire,
	// so the cast header records the subsystem name instead — this is
	// what identifies an SFTP file-transfer session.
	subsystem := ss.Subsystem()

	ch := sessionrecording.CastHeader{
		Version:   2,
		Width:     w.Width,
		Height:    w.Height,
		Timestamp: now.Unix(),
		// Record the raw client-provided command, not a shell-parsed
		// reconstruction: the SSH command is passed to the user's shell
		// verbatim, and the shell lexer silently drops unbalanced quotes,
		// which could otherwise be used to make the recording show a
		// different command than the one that ran. Subsystem sessions
		// have no command; the subsystem name above is recorded instead.
		Command: cmp.Or(subsystem, ss.RawCommand()),
		Env: map[string]string{
			"TERM": term,
			// TODO(bradfitz): anything else important?
			// including all seems noisey, but maybe we should
			// for auditing. But first need to break
			// launchProcess's startWithStdPipes and
			// startWithPTY up so that they first return the cmd
			// without starting it, and then a step that starts
			// it. Then we can (1) make the cmd, (2) start the
			// recording, (3) start the process.
		},
		SSHUser:      ss.conn.info.sshUser,
		LocalUser:    ss.conn.localUser.Username,
		SrcNode:      strings.TrimSuffix(ss.conn.info.node.Name(), "."),
		SrcNodeID:    ss.conn.info.node.StableID(),
		ConnectionID: ss.conn.connID,
	}
	if !ss.conn.info.node.IsTagged() {
		ch.SrcNodeUser = ss.conn.info.uprof.LoginName
		ch.SrcNodeUserID = ss.conn.info.node.User()
	} else {
		ch.SrcNodeTags = ss.conn.info.node.Tags().AsSlice()
	}
	j, err := json.Marshal(ch)
	if err != nil {
		return nil, err
	}
	j = append(j, '\n')
	if _, err := rec.out.Write(j); err != nil {
		if errors.Is(err, io.ErrClosedPipe) && ss.ctx.Err() != nil {
			// If we got an io.ErrClosedPipe, it's likely because
			// the recording server closed the connection on us. Return
			// the original context error instead.
			return nil, context.Cause(ss.ctx)
		}
		return nil, err
	}
	return rec, nil
}

// notifyControl sends a SSHEventNotifyRequest to control over noise.
// A SSHEventNotifyRequest is sent when an action or state reached during
// an SSH session is a defined EventType. Each notification is bounded so
// an unresponsive control request cannot indefinitely block session startup
// after a recorder connection failure or retain an upload watcher. The
// timeout is local to the notification, not the recording upload or session.
func (ss *sshSession) notifyControl(ctx context.Context, nodeKey key.NodePublic, notifyType tailcfg.SSHEventType, attempts []*tailcfg.SSHRecordingAttempt, url string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	re := tailcfg.SSHEventNotifyRequest{
		EventType:         notifyType,
		ConnectionID:      ss.conn.connID,
		CapVersion:        tailcfg.CurrentCapabilityVersion,
		NodeKey:           nodeKey,
		SrcNode:           ss.conn.info.node.ID(),
		SSHUser:           ss.conn.info.sshUser,
		LocalUser:         ss.conn.localUser.Username,
		RecordingAttempts: attempts,
	}

	body, err := json.Marshal(re)
	if err != nil {
		ss.logf("notifyControl: unable to marshal SSHNotifyRequest:", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, httpm.POST, url, bytes.NewReader(body))
	if err != nil {
		ss.logf("notifyControl: unable to create request:", err)
		return
	}

	resp, err := ss.conn.srv.lb.DoNoiseRequest(req)
	if err != nil {
		ss.logf("notifyControl: unable to send noise request:", err)
		return
	}

	if resp.StatusCode != http.StatusCreated {
		ss.logf("notifyControl: noise request returned status code %v", resp.StatusCode)
		return
	}
}

// recording is the state for an SSH session recording.
type recording struct {
	ss    *sshSession
	start time.Time

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	// metadataOnly disables I/O recording for subsystem sessions (SFTP).
	// The cast header identifies the peer, local user, connection, and
	// subsystem. Upload and recording-failure policy still apply.
	metadataOnly bool

	mu  sync.Mutex // guards writes to, close of out
	out io.WriteCloser
}

func (r *recording) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.out == nil {
		return nil
	}
	err := r.out.Close()
	r.out = nil
	return err
}

// writer returns an io.Writer around w that first records the write.
//
// The dir should be "i" for input or "o" for output.
//
// If r is nil, it returns w unchanged.
//
// Currently (2023-03-21) we only record output, not input.
func (r *recording) writer(dir string, w io.Writer) io.Writer {
	if r == nil {
		return w
	}
	if r.metadataOnly {
		// Metadata-only recordings (sftp) capture no I/O events.
		return w
	}
	if dir == "i" {
		// TODO: record input? Maybe not, since it might contain
		// passwords.
		return w
	}
	return &loggingWriter{r: r, dir: dir, w: w}
}

// loggingWriter is an io.Writer wrapper that writes first an
// asciinema JSON cast format recording line, and then writes to w.
type loggingWriter struct {
	r   *recording
	dir string    // "i" or "o" (input or output)
	w   io.Writer // underlying Writer, after writing to r.out

	// recordingFailedOpen specifies whether we've failed to write to
	// r.out and should stop trying. It is set to true if we fail to write
	// to r.out and r.failOpen is set.
	recordingFailedOpen bool
}

func (w *loggingWriter) Write(p []byte) (n int, err error) {
	if !w.recordingFailedOpen {
		j, err := json.Marshal([]any{
			time.Since(w.r.start).Seconds(),
			w.dir,
			string(p),
		})
		if err != nil {
			return 0, err
		}
		j = append(j, '\n')
		if err := w.writeCastLine(j); err != nil {
			if !w.r.failOpen {
				return 0, err
			}
			w.recordingFailedOpen = true
		}
	}
	return w.w.Write(p)
}

func (w loggingWriter) writeCastLine(j []byte) error {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if w.r.out == nil {
		return errors.New("logger closed")
	}
	_, err := w.r.out.Write(j)
	if err != nil {
		return fmt.Errorf("logger Write: %w", err)
	}
	return nil
}

func envValFromList(env []string, wantKey string) (v string) {
	for _, kv := range env {
		if thisKey, v, ok := strings.Cut(kv, "="); ok && envEq(thisKey, wantKey) {
			return v
		}
	}
	return ""
}

// envEq reports whether environment variable a == b for the current
// operating system.
func envEq(a, b string) bool {
	//lint:ignore SA4032 in case this func moves elsewhere, permit the GOOS check
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

var (
	metricActiveSessions      = clientmetric.NewGauge("ssh_active_sessions")
	metricIncomingConnections = clientmetric.NewCounter("ssh_incoming_connections")
	metricTerminalAccept      = clientmetric.NewCounter("ssh_terminalaction_accept")
	metricTerminalReject      = clientmetric.NewCounter("ssh_terminalaction_reject")
	metricTerminalMalformed   = clientmetric.NewCounter("ssh_terminalaction_malformed")
	metricTerminalFetchError  = clientmetric.NewCounter("ssh_terminalaction_fetch_error")
	metricHolds               = clientmetric.NewCounter("ssh_holds")
	metricPolicyChangeKick    = clientmetric.NewCounter("ssh_policy_change_kick")
	metricSFTP                = clientmetric.NewCounter("ssh_sftp_sessions")
	metricLocalPortForward    = clientmetric.NewCounter("ssh_local_port_forward_requests")
	metricRemotePortForward   = clientmetric.NewCounter("ssh_remote_port_forward_requests")
)

// userVisibleError is a wrapper around an error that implements
// SSHTerminationError, so msg is written to their session.
type userVisibleError struct {
	msg string
	error
}

func (ue userVisibleError) SSHTerminationMessage() string { return ue.msg }

// SSHTerminationError is implemented by errors that terminate an SSH
// session and should be written to user's sessions.
type SSHTerminationError interface {
	error
	SSHTerminationMessage() string
}

func closeAll(cs ...io.Closer) {
	for _, c := range cs {
		if c != nil {
			c.Close()
		}
	}
}
