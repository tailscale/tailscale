// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

var (
	sshVerboseLogging = envknob.RegisterBool("TS_DEBUG_SSH_VLOG")
)

type server struct {
	lb             *ipnlocal.LocalBackend
	logf           logger.Logf
	tailscaledPath string

	pubKeyHTTPClient *http.Client     // or nil for http.DefaultClient
	timeNow          func() time.Time // or nil for time.Now

	sessionWaitGroup sync.WaitGroup

	// mu protects the following
	mu                   sync.Mutex
	activeConns          map[*conn]bool              // set; value is always true
	fetchPublicKeysCache map[string]pubKeyCacheEntry // by https URL
	shutdownCalled       bool
}

func (srv *server) now() time.Time {
	if srv != nil && srv.timeNow != nil {
		return srv.timeNow()
	}
	return time.Now()
}

func init() {
	ipnlocal.RegisterNewSSHServer(func(logf logger.Logf, lb *ipnlocal.LocalBackend) (ipnlocal.SSHServer, error) {
		tsd, err := os.Executable()
		if err != nil {
			return nil, err
		}
		srv := &server{
			lb:             lb,
			logf:           logf,
			tailscaledPath: tsd,
		}
		return srv, nil
	})
}

func (srv *server) trackActiveConn(c *conn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if add {
		mak.Set(&srv.activeConns, c, true)
		return
	}
	delete(srv.activeConns, c)
}

// HandleSSHConn handles a Tailscale SSH connection from c.
// This is the entry point for all SSH connections.
// When this returns, the connection is closed.
func (srv *server) HandleSSHConn(nc net.Conn) error {
	metricIncomingConnections.Add(1)
	c, err := srv.newConn()
	if err != nil {
		return err
	}
	srv.trackActiveConn(c, true)        // add
	defer srv.trackActiveConn(c, false) // remove
	c.HandleConn(nc)

	// Return nil to signal to netstack's interception that it doesn't need to
	// log. If ss.HandleConn had problems, it can log itself (ideally on an
	// sshSession.logf).
	return nil
}

// Shutdown terminates all active sessions.
func (srv *server) Shutdown() {
	srv.mu.Lock()
	srv.shutdownCalled = true
	for c := range srv.activeConns {
		for _, s := range c.sessions {
			s.ctx.CloseWithError(userVisibleError{
				fmt.Sprintf("Tailscale SSH is shutting down.\r\n"),
				context.Canceled,
			})
		}
	}
	srv.mu.Unlock()
	srv.sessionWaitGroup.Wait()
}

// OnPolicyChange terminates any active sessions that no longer match
// the SSH access policy.
func (srv *server) OnPolicyChange() {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for c := range srv.activeConns {
		c.mu.Lock()
		ci := c.info
		c.mu.Unlock()
		if ci == nil {
			// c.info is nil when the connection hasn't been authenticated yet.
			// In that case, the connection will be terminated when it is.
			continue
		}
		go c.checkStillValid()
	}
}

// conn represents a single SSH connection and its associated
// ssh.Server.
type conn struct {
	*ssh.Server

	insecureSkipTailscaleAuth bool // used by tests.

	connID  string             // ID that's shared with control
	action0 *tailcfg.SSHAction // first matching action
	srv     *server

	mu           sync.Mutex   // protects the following
	localUser    *user.User   // set by checkAuth
	userGroupIDs []string     // set by checkAuth
	info         *sshConnInfo // set by setInfo
	// idH is the RFC4253 sec8 hash H. It is used to identify the connection,
	// and is shared among all sessions. It should not be shared outside
	// process. It is confusingly referred to as SessionID by the gliderlabs/ssh
	// library.
	idH            string
	pubKey         gossh.PublicKey    // set by authorizeSession
	finalAction    *tailcfg.SSHAction // set by authorizeSession
	finalActionErr error              // set by authorizeSession
	sessions       []*sshSession
}

func (c *conn) logf(format string, args ...any) {
	format = fmt.Sprintf("%v: %v", c.connID, format)
	c.srv.logf(format, args...)
}

// PublicKeyHandler implements ssh.PublicKeyHandler is called by the
// ssh.Server when the client presents a public key.
func (c *conn) PublicKeyHandler(ctx ssh.Context, pubKey ssh.PublicKey) error {
	c.mu.Lock()
	ci := c.info
	c.mu.Unlock()
	if ci == nil {
		return gossh.ErrDenied
	}

	if err := c.checkAuth(pubKey); err != nil {
		// TODO(maisem/bradfitz): surface the error here.
		c.logf("rejecting SSH public key %s: %v", bytes.TrimSpace(gossh.MarshalAuthorizedKey(pubKey)), err)
		return err
	}
	c.logf("accepting SSH public key %s", bytes.TrimSpace(gossh.MarshalAuthorizedKey(pubKey)))
	return nil
}

// errPubKeyRequired is returned by NoClientAuthCallback to make the client
// resort to public-key auth; not user visible.
var errPubKeyRequired = errors.New("ssh publickey required")

// NoClientAuthCallback implements gossh.NoClientAuthCallback and is called by
// the ssh.Server when the client first connects with the "none"
// authentication method.
func (c *conn) NoClientAuthCallback(cm gossh.ConnMetadata) (*gossh.Permissions, error) {
	if c.insecureSkipTailscaleAuth {
		return nil, nil
	}
	if err := c.setInfo(cm); err != nil {
		c.logf("failed to get conninfo: %v", err)
		return nil, gossh.ErrDenied
	}
	return nil, c.checkAuth(nil /* no pub key */)
}

// checkAuth verifies that conn can proceed with the specified (optional)
// pubKey. It returns nil if the matching policy action is Accept or
// HoldAndDelegate. If pubKey is nil, there was no policy match but there is a
// policy that might match a public key it returns errPubKeyRequired. Otherwise,
// it returns gossh.ErrDenied possibly wrapped in gossh.WithBannerError.
func (c *conn) checkAuth(pubKey ssh.PublicKey) error {
	a, localUser, err := c.evaluatePolicy(pubKey)
	if err != nil {
		if pubKey == nil && c.havePubKeyPolicy() {
			return errPubKeyRequired
		}
		return fmt.Errorf("%w: %v", gossh.ErrDenied, err)
	}
	c.action0 = a
	if a.Accept || a.HoldAndDelegate != "" {
		lu, err := user.Lookup(localUser)
		if err != nil {
			c.logf("failed to lookup %v: %v", localUser, err)
			return gossh.WithBannerError{
				Err:     gossh.ErrDenied,
				Message: fmt.Sprintf("failed to lookup %v\r\n", localUser),
			}
		}
		gids, err := lu.GroupIds()
		if err != nil {
			return err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.userGroupIDs = gids
		c.localUser = lu
		return nil
	}
	if a.Reject {
		err := gossh.ErrDenied
		if a.Message != "" {
			err = gossh.WithBannerError{
				Err:     err,
				Message: a.Message,
			}
		}
		return err
	}
	// Shouldn't get here, but:
	return gossh.ErrDenied
}

// ServerConfig implements ssh.ServerConfigCallback.
func (c *conn) ServerConfig(ctx ssh.Context) *gossh.ServerConfig {
	return &gossh.ServerConfig{
		// OpenSSH presents this on failure as `Permission denied (tailscale).`
		ImplictAuthMethod:    "tailscale",
		NoClientAuth:         true, // required for the NoClientAuthCallback to run
		NoClientAuthCallback: c.NoClientAuthCallback,
	}
}

func (srv *server) newConn() (*conn, error) {
	srv.mu.Lock()
	if srv.shutdownCalled {
		srv.mu.Unlock()
		// Stop accepting new connections.
		// Connections in the auth phase are handled in handleConnPostSSHAuth.
		// Existing sessions are terminated by Shutdown.
		return nil, gossh.ErrDenied
	}
	srv.mu.Unlock()
	c := &conn{srv: srv}
	now := srv.now()
	c.connID = fmt.Sprintf("ssh-conn-%s-%02x", now.UTC().Format("20060102T150405"), randBytes(5))
	c.Server = &ssh.Server{
		Version:         "Tailscale",
		Handler:         c.handleSessionPostSSHAuth,
		RequestHandlers: map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": c.handleSessionPostSSHAuth,
		},

		// Note: the direct-tcpip channel handler and LocalPortForwardingCallback
		// only adds support for forwarding ports from the local machine.
		// TODO(maisem/bradfitz): add remote port forwarding support.
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		LocalPortForwardingCallback: c.mayForwardLocalPortTo,

		PublicKeyHandler:     c.PublicKeyHandler,
		ServerConfigCallback: c.ServerConfig,
	}
	ss := c.Server
	for k, v := range ssh.DefaultRequestHandlers {
		ss.RequestHandlers[k] = v
	}
	for k, v := range ssh.DefaultChannelHandlers {
		ss.ChannelHandlers[k] = v
	}
	for k, v := range ssh.DefaultSubsystemHandlers {
		ss.SubsystemHandlers[k] = v
	}
	keys, err := srv.lb.GetSSH_HostKeys()
	if err != nil {
		return nil, err
	}
	for _, signer := range keys {
		ss.AddHostKey(signer)
	}
	return c, nil
}

// mayForwardLocalPortTo reports whether the ctx should be allowed to port forward
// to the specified host and port.
// TODO(bradfitz/maisem): should we have more checks on host/port?
func (c *conn) mayForwardLocalPortTo(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	if c.finalAction != nil && c.finalAction.AllowLocalPortForwarding {
		metricLocalPortForward.Add(1)
		return true
	}
	return false
}

// havePubKeyPolicy reports whether any policy rule may provide access by means
// of a ssh.PublicKey.
func (c *conn) havePubKeyPolicy() bool {
	c.mu.Lock()
	ci := c.info
	c.mu.Unlock()
	if ci == nil {
		panic("havePubKeyPolicy called before setInfo")
	}
	// Is there any rule that looks like it'd require a public key for this
	// sshUser?
	pol, ok := c.sshPolicy()
	if !ok {
		return false
	}
	for _, r := range pol.Rules {
		if c.ruleExpired(r) {
			continue
		}
		if mapLocalUser(r.SSHUsers, ci.sshUser) == "" {
			continue
		}
		for _, p := range r.Principals {
			if len(p.PubKeys) > 0 && c.principalMatchesTailscaleIdentity(p) {
				return true
			}
		}
	}
	return false
}

// sshPolicy returns the SSHPolicy for current node.
// If there is no SSHPolicy in the netmap, it returns a debugPolicy
// if one is defined.
func (c *conn) sshPolicy() (_ *tailcfg.SSHPolicy, ok bool) {
	lb := c.srv.lb
	if !lb.ShouldRunSSH() {
		return nil, false
	}
	nm := lb.NetMap()
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

// connInfo returns a populated sshConnInfo from the provided arguments,
// validating only that they represent a known Tailscale identity.
func (c *conn) setInfo(cm gossh.ConnMetadata) error {
	ci := &sshConnInfo{
		sshUser: cm.User(),
		src:     toIPPort(cm.RemoteAddr()),
		dst:     toIPPort(cm.LocalAddr()),
	}
	if !tsaddr.IsTailscaleIP(ci.dst.Addr()) {
		return fmt.Errorf("tailssh: rejecting non-Tailscale local address %v", ci.dst)
	}
	if !tsaddr.IsTailscaleIP(ci.src.Addr()) {
		return fmt.Errorf("tailssh: rejecting non-Tailscale remote address %v", ci.src)
	}
	node, uprof, ok := c.srv.lb.WhoIs(ci.src)
	if !ok {
		return fmt.Errorf("unknown Tailscale identity from src %v", ci.src)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ci.node = node
	ci.uprof = &uprof

	c.info = ci
	c.logf("handling conn: %v", ci.String())
	return nil
}

// evaluatePolicy returns the SSHAction and localUser after evaluating
// the SSHPolicy for this conn. The pubKey may be nil for "none" auth.
func (c *conn) evaluatePolicy(pubKey gossh.PublicKey) (_ *tailcfg.SSHAction, localUser string, _ error) {
	pol, ok := c.sshPolicy()
	if !ok {
		return nil, "", fmt.Errorf("tailssh: rejecting connection; no SSH policy")
	}
	a, localUser, ok := c.evalSSHPolicy(pol, pubKey)
	if !ok {
		return nil, "", fmt.Errorf("tailssh: rejecting connection; no matching policy")
	}
	return a, localUser, nil
}

// pubKeyCacheEntry is the cache value for an HTTPS URL of public keys (like
// "https://github.com/foo.keys")
type pubKeyCacheEntry struct {
	lines []string
	etag  string // if sent by server
	at    time.Time
}

const (
	pubKeyCacheDuration      = time.Minute      // how long to cache non-empty public keys
	pubKeyCacheEmptyDuration = 15 * time.Second // how long to cache empty responses
)

func (srv *server) fetchPublicKeysURLCached(url string) (ce pubKeyCacheEntry, ok bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	// Mostly don't care about the size of this cache. Clean rarely.
	if m := srv.fetchPublicKeysCache; len(m) > 50 {
		tooOld := srv.now().Add(pubKeyCacheDuration * 10)
		for k, ce := range m {
			if ce.at.Before(tooOld) {
				delete(m, k)
			}
		}
	}
	ce, ok = srv.fetchPublicKeysCache[url]
	if !ok {
		return ce, false
	}
	maxAge := pubKeyCacheDuration
	if len(ce.lines) == 0 {
		maxAge = pubKeyCacheEmptyDuration
	}
	return ce, srv.now().Sub(ce.at) < maxAge
}

func (srv *server) pubKeyClient() *http.Client {
	if srv.pubKeyHTTPClient != nil {
		return srv.pubKeyHTTPClient
	}
	return http.DefaultClient
}

// fetchPublicKeysURL fetches the public keys from a URL. The strings are in the
// the typical public key "type base64-string [comment]" format seen at e.g.
// https://github.com/USER.keys
func (srv *server) fetchPublicKeysURL(url string) ([]string, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("invalid URL scheme")
	}

	ce, ok := srv.fetchPublicKeysURLCached(url)
	if ok {
		return ce.lines, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if ce.etag != "" {
		req.Header.Add("If-None-Match", ce.etag)
	}
	res, err := srv.pubKeyClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var lines []string
	var etag string
	switch res.StatusCode {
	default:
		err = fmt.Errorf("unexpected status %v", res.Status)
		srv.logf("fetching public keys from %s: %v", url, err)
	case http.StatusNotModified:
		lines = ce.lines
		etag = ce.etag
	case http.StatusOK:
		var all []byte
		all, err = io.ReadAll(io.LimitReader(res.Body, 4<<10))
		if s := strings.TrimSpace(string(all)); s != "" {
			lines = strings.Split(s, "\n")
		}
		etag = res.Header.Get("Etag")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	mak.Set(&srv.fetchPublicKeysCache, url, pubKeyCacheEntry{
		at:    srv.now(),
		lines: lines,
		etag:  etag,
	})
	return lines, err
}

func (c *conn) authorizeSession(s ssh.Session) (_ *contextReader, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idH := s.Context().(ssh.Context).SessionID()
	if c.idH == "" {
		c.idH = idH
	} else if c.idH != idH {
		c.logf("ssh: session ID mismatch: %q != %q", c.idH, idH)
		s.Exit(1)
		return nil, false
	}
	cr := &contextReader{r: s}
	action, err := c.resolveTerminalActionLocked(s, cr)
	if err != nil {
		c.logf("resolveTerminalAction: %v", err)
		io.WriteString(s.Stderr(), "Access Denied: failed during authorization check.\r\n")
		s.Exit(1)
		return nil, false
	}
	if action.Reject || !action.Accept {
		c.logf("access denied for %v", c.info.uprof.LoginName)
		s.Exit(1)
		return nil, false
	}
	return cr, true
}

// handleSessionPostSSHAuth runs an SSH session after the SSH-level authentication,
// but not necessarily before all the Tailscale-level extra verification has
// completed. It also handles SFTP requests.
func (c *conn) handleSessionPostSSHAuth(s ssh.Session) {
	// Now that we have passed the SSH-level authentication, we can start the
	// Tailscale-level extra verification. This means that we are going to
	// evaluate the policy provided by control against the incoming SSH session.
	cr, ok := c.authorizeSession(s)
	if !ok {
		return
	}
	if cr.HasOutstandingRead() {
		// There was some buffered input while we were waiting for the policy
		// decision.
		s = contextReaderSession{s, cr}
	}

	// Do this check after auth, but before starting the session.
	switch s.Subsystem() {
	case "sftp", "":
		metricSFTP.Add(1)
	default:
		fmt.Fprintf(s.Stderr(), "Unsupported subsystem %q\r\n", s.Subsystem())
		s.Exit(1)
		return
	}

	ss := c.newSSHSession(s)
	c.mu.Lock()
	ss.logf("handling new SSH connection from %v (%v) to ssh-user %q", c.info.uprof.LoginName, c.info.src.Addr(), c.localUser.Username)
	ss.logf("access granted to %v as ssh-user %q", c.info.uprof.LoginName, c.localUser.Username)
	c.mu.Unlock()
	ss.run()
}

// resolveTerminalActionLocked either returns action0 (if it's Accept or Reject) or
// else loops, fetching new SSHActions from the control plane.
//
// Any action with a Message in the chain will be printed to s.
//
// The returned SSHAction will be either Reject or Accept.
//
// c.mu must be held.
func (c *conn) resolveTerminalActionLocked(s ssh.Session, cr *contextReader) (action *tailcfg.SSHAction, err error) {
	if c.finalAction != nil || c.finalActionErr != nil {
		return c.finalAction, c.finalActionErr
	}

	if s.PublicKey() != nil {
		metricPublicKeyConnections.Add(1)
	}
	defer func() {
		c.finalAction = action
		c.finalActionErr = err
		c.pubKey = s.PublicKey()
		if c.pubKey != nil && action.Accept {
			metricPublicKeyAccepts.Add(1)
		}
	}()
	action = c.action0

	var awaitReadOnce sync.Once // to start Reads on cr
	var sawInterrupt atomic.Bool
	var wg sync.WaitGroup
	defer wg.Wait() // wait for awaitIntrOnce's goroutine to exit

	ctx, cancel := context.WithCancel(s.Context())
	defer cancel()

	// Loop processing/fetching Actions until one reaches a
	// terminal state (Accept, Reject, or invalid Action), or
	// until fetchSSHAction times out due to the context being
	// done (client disconnect) or its 30 minute timeout passes.
	// (Which is a long time for somebody to see login
	// instructions and go to a URL to do something.)
	for {
		if action.Message != "" {
			io.WriteString(s.Stderr(), strings.Replace(action.Message, "\n", "\r\n", -1))
		}
		if action.Accept || action.Reject {
			if action.Reject {
				metricTerminalReject.Add(1)
			} else {
				metricTerminalAccept.Add(1)
			}
			return action, nil
		}
		url := action.HoldAndDelegate
		if url == "" {
			metricTerminalMalformed.Add(1)
			return nil, errors.New("reached Action that lacked Accept, Reject, and HoldAndDelegate")
		}
		metricHolds.Add(1)
		awaitReadOnce.Do(func() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 1)
				for {
					n, err := cr.ReadContext(ctx, buf)
					if err != nil {
						return
					}
					if n > 0 && buf[0] == 0x03 { // Ctrl-C
						sawInterrupt.Store(true)
						s.Stderr().Write([]byte("Canceled.\r\n"))
						s.Exit(1)
						return
					}
				}
			}()
		})
		url = c.expandDelegateURLLocked(url)
		var err error
		action, err = c.fetchSSHAction(ctx, url)
		if err != nil {
			if sawInterrupt.Load() {
				metricTerminalInterrupt.Add(1)
				return nil, fmt.Errorf("aborted by user")
			} else {
				metricTerminalFetchError.Add(1)
			}
			return nil, fmt.Errorf("fetching SSHAction from %s: %w", url, err)
		}
	}
}

func (c *conn) expandDelegateURLLocked(actionURL string) string {
	nm := c.srv.lb.NetMap()
	ci := c.info
	lu := c.localUser
	var dstNodeID string
	if nm != nil {
		dstNodeID = fmt.Sprint(int64(nm.SelfNode.ID))
	}
	return strings.NewReplacer(
		"$SRC_NODE_IP", url.QueryEscape(ci.src.Addr().String()),
		"$SRC_NODE_ID", fmt.Sprint(int64(ci.node.ID)),
		"$DST_NODE_IP", url.QueryEscape(ci.dst.Addr().String()),
		"$DST_NODE_ID", dstNodeID,
		"$SSH_USER", url.QueryEscape(ci.sshUser),
		"$LOCAL_USER", url.QueryEscape(lu.Username),
	).Replace(actionURL)
}

func (c *conn) expandPublicKeyURL(pubKeyURL string) string {
	if !strings.Contains(pubKeyURL, "$") {
		return pubKeyURL
	}
	var localPart string
	var loginName string
	c.mu.Lock()
	if c.info.uprof != nil {
		loginName = c.info.uprof.LoginName
		localPart, _, _ = strings.Cut(loginName, "@")
	}
	c.mu.Unlock()
	return strings.NewReplacer(
		"$LOGINNAME_EMAIL", loginName,
		"$LOGINNAME_LOCALPART", localPart,
	).Replace(pubKeyURL)
}

// sshSession is an accepted Tailscale SSH session.
type sshSession struct {
	ssh.Session
	sharedID string // ID that's shared with control
	logf     logger.Logf

	ctx           *sshContext // implements context.Context
	conn          *conn
	agentListener net.Listener // non-nil if agent-forwarding requested+allowed

	// initialized by launchProcess:
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.Reader // nil for pty sessions
	ptyReq *ssh.Pty  // non-nil for pty sessions

	// We use this sync.Once to ensure that we only terminate the process once,
	// either it exits itself or is terminated
	exitOnce sync.Once
}

func (ss *sshSession) vlogf(format string, args ...interface{}) {
	if sshVerboseLogging() {
		ss.logf(format, args...)
	}
}

func (c *conn) newSSHSession(s ssh.Session) *sshSession {
	sharedID := fmt.Sprintf("sess-%s-%02x", c.srv.now().UTC().Format("20060102T150405"), randBytes(5))
	c.logf("starting session: %v", sharedID)
	return &sshSession{
		Session:  s,
		sharedID: sharedID,
		ctx:      newSSHContext(),
		conn:     c,
		logf:     logger.WithPrefix(c.srv.logf, "ssh-session("+sharedID+"): "),
	}
}

// isStillValid reports whether the conn is still valid.
func (c *conn) isStillValid() bool {
	a, localUser, err := c.evaluatePolicy(c.pubKey)
	if err != nil {
		return false
	}
	if !a.Accept && a.HoldAndDelegate == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localUser.Username == localUser
}

// checkStillValid checks that the conn is still valid per the latest SSHPolicy.
// If not, it terminates all sessions associated with the conn.
func (c *conn) checkStillValid() {
	if c.isStillValid() {
		return
	}
	metricPolicyChangeKick.Add(1)
	c.logf("session no longer valid per new SSH policy; closing")
	for _, s := range c.sessions {
		s.ctx.CloseWithError(userVisibleError{
			fmt.Sprintf("Access revoked.\r\n"),
			context.Canceled,
		})
	}
}

func (c *conn) fetchSSHAction(ctx context.Context, url string) (*tailcfg.SSHAction, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
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
	<-ss.ctx.Done()
	// Either the process has already exited, in which case this does nothing.
	// Or, the process is still running in which case this will kill it.
	ss.exitOnce.Do(func() {
		err := ss.ctx.Err()
		if serr, ok := err.(SSHTerminationError); ok {
			msg := serr.SSHTerminationMessage()
			if msg != "" {
				io.WriteString(ss.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
			}
		}
		ss.logf("terminating SSH session from %v: %v", ss.conn.info.src.Addr(), err)
		// We don't need to Process.Wait here, sshSession.run() does
		// the waiting regardless of termination reason.

		// TODO(maisem): should this be a SIGTERM followed by a SIGKILL?
		ss.cmd.Process.Kill()
	})
}

// startSessionLocked registers ss as an active session.
// It must be called with srv.mu held.
func (c *conn) startSessionLocked(ss *sshSession) {
	c.srv.sessionWaitGroup.Add(1)
	if ss.sharedID == "" {
		panic("empty sharedID")
	}
	c.sessions = append(c.sessions, ss)
}

// endSession unregisters s from the list of active sessions.
func (c *conn) endSession(ss *sshSession) {
	defer c.srv.sessionWaitGroup.Done()
	c.srv.mu.Lock()
	defer c.srv.mu.Unlock()
	for i, s := range c.sessions {
		if s == ss {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			break
		}
	}
}

var errSessionDone = errors.New("session is done")

// handleSSHAgentForwarding starts a Unix socket listener and in the background
// forwards agent connections between the listener and the ssh.Session.
// On success, it assigns ss.agentListener.
func (ss *sshSession) handleSSHAgentForwarding(s ssh.Session, lu *user.User) error {
	if !ssh.AgentRequested(ss) || !ss.conn.finalAction.AllowAgentForwarding {
		return nil
	}
	ss.logf("ssh: agent forwarding requested")
	ln, err := ssh.NewAgentListener()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && ln != nil {
			ln.Close()
		}
	}()

	uid, err := strconv.ParseUint(lu.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(lu.Gid, 10, 32)
	if err != nil {
		return err
	}
	socket := ln.Addr().String()
	dir := filepath.Dir(socket)
	// Make sure the socket is accessible only by the user.
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	if err := os.Chown(socket, int(uid), int(gid)); err != nil {
		return err
	}
	// Make sure the dir is also accessible.
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}

	go ssh.ForwardAgentConnections(ln, s)
	ss.agentListener = ln
	return nil
}

// recordSSH is a temporary dev knob to test the SSH recording
// functionality and support off-node streaming.
//
// TODO(bradfitz,maisem): move this to SSHPolicy.
var recordSSH = envknob.RegisterBool("TS_DEBUG_LOG_SSH")

// run is the entrypoint for a newly accepted SSH session.
//
// It handles ss once it's been accepted and determined
// that it should run.
func (ss *sshSession) run() {
	metricActiveSessions.Add(1)
	defer metricActiveSessions.Add(-1)
	defer ss.ctx.CloseWithError(errSessionDone)
	srv := ss.conn.srv

	srv.mu.Lock()
	if srv.shutdownCalled {
		srv.mu.Unlock()
		// Do not start any new sessions.
		fmt.Fprintf(ss, "Tailscale SSH is shutting down\r\n")
		ss.Exit(1)
		return
	}
	ss.conn.startSessionLocked(ss)
	lu := ss.conn.localUser
	localUser := lu.Username
	srv.mu.Unlock()

	defer ss.conn.endSession(ss)

	if ss.conn.finalAction.SessionDuration != 0 {
		t := time.AfterFunc(ss.conn.finalAction.SessionDuration, func() {
			ss.ctx.CloseWithError(userVisibleError{
				fmt.Sprintf("Session timeout of %v elapsed.", ss.conn.finalAction.SessionDuration),
				context.DeadlineExceeded,
			})
		})
		defer t.Stop()
	}

	logf := ss.logf

	if euid := os.Geteuid(); euid != 0 {
		if lu.Uid != fmt.Sprint(euid) {
			ss.logf("can't switch to user %q from process euid %v", localUser, euid)
			fmt.Fprintf(ss, "can't switch user\r\n")
			ss.Exit(1)
			return
		}
	}

	// Take control of the PTY so that we can configure it below.
	// See https://github.com/tailscale/tailscale/issues/4146
	ss.DisablePTYEmulation()

	var rec *recording // or nil if disabled
	if ss.Subsystem() != "sftp" {
		if err := ss.handleSSHAgentForwarding(ss, lu); err != nil {
			ss.logf("agent forwarding failed: %v", err)
		} else if ss.agentListener != nil {
			// TODO(maisem/bradfitz): add a way to close all session resources
			defer ss.agentListener.Close()
		}

		if ss.shouldRecord() {
			var err error
			rec, err = ss.startNewRecording()
			if err != nil {
				fmt.Fprintf(ss, "can't start new recording\r\n")
				ss.logf("startNewRecording: %v", err)
				ss.Exit(1)
				return
			}
			defer rec.Close()
		}
	}

	err := ss.launchProcess()
	if err != nil {
		logf("start failed: %v", err.Error())
		ss.Exit(1)
		return
	}
	go ss.killProcessOnContextDone()

	go func() {
		defer ss.stdin.Close()
		if _, err := io.Copy(rec.writer("i", ss.stdin), ss); err != nil {
			logf("stdin copy: %v", err)
			ss.ctx.CloseWithError(err)
		} else if ss.ptyReq != nil {
			const EOT = 4 // https://en.wikipedia.org/wiki/End-of-Transmission_character
			ss.stdin.Write([]byte{EOT})
		}
	}()
	go func() {
		defer ss.stdout.Close()
		_, err := io.Copy(rec.writer("o", ss), ss.stdout)
		if err != nil && !errors.Is(err, io.EOF) {
			logf("stdout copy: %v", err)
			ss.ctx.CloseWithError(err)
		} else {
			ss.CloseWrite()
		}
	}()
	// stderr is nil for ptys.
	if ss.stderr != nil {
		go func() {
			_, err := io.Copy(ss.Stderr(), ss.stderr)
			if err != nil {
				logf("stderr copy: %v", err)
			}
		}()
	}

	err = ss.cmd.Wait()
	// This will either make the SSH Termination goroutine be a no-op,
	// or itself will be a no-op because the process was killed by the
	// aforementioned goroutine.
	ss.exitOnce.Do(func() {})

	if err == nil {
		ss.logf("Session complete")
		ss.Exit(0)
		return
	}
	if ee, ok := err.(*exec.ExitError); ok {
		code := ee.ProcessState.ExitCode()
		ss.logf("Wait: code=%v", code)
		ss.Exit(code)
		return
	}

	ss.logf("Wait: %v", err)
	ss.Exit(1)
	return
}

func (ss *sshSession) shouldRecord() bool {
	// for now only record pty sessions
	// TODO(bradfitz,maisem): make configurable on SSHPolicy and
	// support recording non-pty stuff too.
	_, _, isPtyReq := ss.Pty()
	return recordSSH() && isPtyReq
}

type sshConnInfo struct {
	// sshUser is the requested local SSH username ("root", "alice", etc).
	sshUser string

	// src is the Tailscale IP and port that the connection came from.
	src netip.AddrPort

	// dst is the Tailscale IP and port that the connection came for.
	dst netip.AddrPort

	// node is srcIP's node.
	node *tailcfg.Node

	// uprof is node's UserProfile.
	uprof *tailcfg.UserProfile
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

func (c *conn) evalSSHPolicy(pol *tailcfg.SSHPolicy, pubKey gossh.PublicKey) (a *tailcfg.SSHAction, localUser string, ok bool) {
	for _, r := range pol.Rules {
		if a, localUser, err := c.matchRule(r, pubKey); err == nil {
			return a, localUser, true
		}
	}
	return nil, "", false
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

func (c *conn) matchRule(r *tailcfg.SSHRule, pubKey gossh.PublicKey) (a *tailcfg.SSHAction, localUser string, err error) {
	if c == nil {
		return nil, "", errInvalidConn
	}
	c.mu.Lock()
	ci := c.info
	c.mu.Unlock()
	if ci == nil {
		c.logf("invalid connection state")
		return nil, "", errInvalidConn
	}
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if c.ruleExpired(r) {
		return nil, "", errRuleExpired
	}
	if !r.Action.Reject {
		// For all but Reject rules, SSHUsers is required.
		// If SSHUsers is nil or empty, mapLocalUser will return an
		// empty string anyway.
		localUser = mapLocalUser(r.SSHUsers, ci.sshUser)
		if localUser == "" {
			return nil, "", errUserMatch
		}
	}
	if ok, err := c.anyPrincipalMatches(r.Principals, pubKey); err != nil {
		return nil, "", err
	} else if !ok {
		return nil, "", errPrincipalMatch
	}
	return r.Action, localUser, nil
}

func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string) (localUser string) {
	v, ok := ruleSSHUsers[reqSSHUser]
	if !ok {
		v = ruleSSHUsers["*"]
	}
	if v == "=" {
		return reqSSHUser
	}
	return v
}

func (c *conn) anyPrincipalMatches(ps []*tailcfg.SSHPrincipal, pubKey gossh.PublicKey) (bool, error) {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if ok, err := c.principalMatches(p, pubKey); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

func (c *conn) principalMatches(p *tailcfg.SSHPrincipal, pubKey gossh.PublicKey) (bool, error) {
	if !c.principalMatchesTailscaleIdentity(p) {
		return false, nil
	}
	return c.principalMatchesPubKey(p, pubKey)
}

// principalMatchesTailscaleIdentity reports whether one of p's four fields
// that match the Tailscale identity match (Node, NodeIP, UserLogin, Any).
// This function does not consider PubKeys.
func (c *conn) principalMatchesTailscaleIdentity(p *tailcfg.SSHPrincipal) bool {
	c.mu.Lock()
	ci := c.info
	c.mu.Unlock()
	if p.Any {
		return true
	}
	if !p.Node.IsZero() && ci.node != nil && p.Node == ci.node.StableID {
		return true
	}
	if p.NodeIP != "" {
		if ip, _ := netip.ParseAddr(p.NodeIP); ip == ci.src.Addr() {
			return true
		}
	}
	if p.UserLogin != "" && ci.uprof != nil && ci.uprof.LoginName == p.UserLogin {
		return true
	}
	return false
}

func (c *conn) principalMatchesPubKey(p *tailcfg.SSHPrincipal, clientPubKey gossh.PublicKey) (bool, error) {
	if len(p.PubKeys) == 0 {
		return true, nil
	}
	if clientPubKey == nil {
		return false, nil
	}
	knownKeys := p.PubKeys
	if len(knownKeys) == 1 && strings.HasPrefix(knownKeys[0], "https://") {
		var err error
		knownKeys, err = c.srv.fetchPublicKeysURL(c.expandPublicKeyURL(knownKeys[0]))
		if err != nil {
			return false, err
		}
	}
	for _, knownKey := range knownKeys {
		if pubKeyMatchesAuthorizedKey(clientPubKey, knownKey) {
			return true, nil
		}
	}
	return false, nil
}

func pubKeyMatchesAuthorizedKey(pubKey ssh.PublicKey, wantKey string) bool {
	wantKeyType, rest, ok := strings.Cut(wantKey, " ")
	if !ok {
		return false
	}
	if pubKey.Type() != wantKeyType {
		return false
	}
	wantKeyB64, _, _ := strings.Cut(rest, " ")
	wantKeyData, _ := base64.StdEncoding.DecodeString(wantKeyB64)
	return len(wantKeyData) > 0 && bytes.Equal(pubKey.Marshal(), wantKeyData)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// startNewRecording starts a new SSH session recording.
//
// It writes an asciinema file to
// $TAILSCALE_VAR_ROOT/ssh-sessions/ssh-session-<unixtime>-*.cast.
func (ss *sshSession) startNewRecording() (*recording, error) {
	var w ssh.Window
	if ptyReq, _, isPtyReq := ss.Pty(); isPtyReq {
		w = ptyReq.Window
	}

	term := envValFromList(ss.Environ(), "TERM")
	if term == "" {
		term = "xterm-256color" // something non-empty
	}

	now := time.Now()
	rec := &recording{
		ss:    ss,
		start: now,
	}
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
	rec.out = f

	// {"version": 2, "width": 221, "height": 84, "timestamp": 1647146075, "env": {"SHELL": "/bin/bash", "TERM": "screen"}}
	type CastHeader struct {
		Version   int               `json:"version"`
		Width     int               `json:"width"`
		Height    int               `json:"height"`
		Timestamp int64             `json:"timestamp"`
		Env       map[string]string `json:"env"`
	}
	j, err := json.Marshal(CastHeader{
		Version:   2,
		Width:     w.Width,
		Height:    w.Height,
		Timestamp: now.Unix(),
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
	})
	if err != nil {
		f.Close()
		return nil, err
	}
	ss.logf("starting asciinema recording to %s", f.Name())
	j = append(j, '\n')
	if _, err := f.Write(j); err != nil {
		f.Close()
		return nil, err
	}
	return rec, nil
}

// recording is the state for an SSH session recording.
type recording struct {
	ss    *sshSession
	start time.Time

	mu  sync.Mutex // guards writes to, close of out
	out *os.File   // nil if closed
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
func (r *recording) writer(dir string, w io.Writer) io.Writer {
	if r == nil {
		return w
	}
	return &loggingWriter{r, dir, w}
}

// loggingWriter is an io.Writer wrapper that writes first an
// asciinema JSON cast format recording line, and then writes to w.
type loggingWriter struct {
	r   *recording
	dir string    // "i" or "o" (input or output)
	w   io.Writer // underlying Writer, after writing to r.out
}

func (w loggingWriter) Write(p []byte) (n int, err error) {
	j, err := json.Marshal([]interface{}{
		time.Since(w.r.start).Seconds(),
		w.dir,
		string(p),
	})
	if err != nil {
		return 0, err
	}
	j = append(j, '\n')
	if err := w.writeCastLine(j); err != nil {
		return 0, err
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
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

var (
	metricActiveSessions       = clientmetric.NewGauge("ssh_active_sessions")
	metricIncomingConnections  = clientmetric.NewCounter("ssh_incoming_connections")
	metricPublicKeyConnections = clientmetric.NewCounter("ssh_publickey_connections") // total
	metricPublicKeyAccepts     = clientmetric.NewCounter("ssh_publickey_accepts")     // accepted subset of ssh_publickey_connections
	metricTerminalAccept       = clientmetric.NewCounter("ssh_terminalaction_accept")
	metricTerminalReject       = clientmetric.NewCounter("ssh_terminalaction_reject")
	metricTerminalInterrupt    = clientmetric.NewCounter("ssh_terminalaction_interrupt")
	metricTerminalMalformed    = clientmetric.NewCounter("ssh_terminalaction_malformed")
	metricTerminalFetchError   = clientmetric.NewCounter("ssh_terminalaction_fetch_error")
	metricHolds                = clientmetric.NewCounter("ssh_holds")
	metricPolicyChangeKick     = clientmetric.NewCounter("ssh_policy_change_kick")
	metricSFTP                 = clientmetric.NewCounter("ssh_sftp_requests")
	metricLocalPortForward     = clientmetric.NewCounter("ssh_local_port_forward_requests")
)
