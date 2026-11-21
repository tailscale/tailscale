// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"errors"
	"fmt"
	"sync"

	"tailscale.com/util/winutil"
	"tailscale.com/util/winutil/s4u"
)

// connMonitorState holds the Windows per-connection forwarding state.
//
// Windows has no monitor process like the unix platforms: session
// processes run under the target user's token directly (see
// process_windows.go), and forwarded sockets are dialed and bound by
// this tailscaled while impersonating the connection's user. The only
// per-connection resource is the S4U session used for that impersonation,
// created lazily on the first forward and closed at connection teardown.
//
// When tailscaled is not LocalSystem it already runs as the target user,
// so no impersonation session is needed and sess stays nil.
type connMonitorState struct {
	mu     sync.Mutex
	closed bool
	sess   *s4u.Session // nil until the first forward as LocalSystem
}

// close closes the impersonation session, if any, and refuses later
// forwards. It is called once at connection teardown.
func (s *connMonitorState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.sess != nil {
		s.sess.Close()
		s.sess = nil
	}
}

func (c *conn) closeConnMonitor() { c.monitor.close() }

// fwdImpersonate runs fn with the connection user's Windows identity in
// effect, so that a forwarded socket's dial or bind is attributed to that
// user rather than to LocalSystem. As LocalSystem it impersonates the user
// through a lazily-created S4U session; otherwise this tailscaled already
// runs as the user and fn runs directly.
//
// Only the socket creation, connect, and bind inside fn need to run under
// the user. Later reads and writes on the returned connection may run
// unimpersonated, as they do with the unix monitor's children.
func (c *conn) fwdImpersonate(fn func()) error {
	sess, err := c.fwdSession()
	if err != nil {
		return err
	}
	if sess == nil {
		fn()
		return nil
	}
	return sess.Do(fn)
}

// fwdSession returns the connection's impersonation session, creating it on
// first use, or nil when tailscaled already runs as the target user.
func (c *conn) fwdSession() (*s4u.Session, error) {
	if !winutil.IsCurrentProcessLocalSystem() {
		// tailscaled is already the target user; see canSwitchToLocalUser.
		return nil, nil
	}
	c.monitor.mu.Lock()
	defer c.monitor.mu.Unlock()
	if c.monitor.closed {
		return nil, errors.New("ssh: connection is closing")
	}
	if c.monitor.sess != nil {
		return c.monitor.sess, nil
	}
	lu := c.localUser
	sess, err := s4u.Login(c.logf, s4uSourceName, &lu.User, s4u.CapImpersonateOnly)
	if err != nil {
		return nil, fmt.Errorf("ssh: S4U login to forward as %q: %w", lu.Username, err)
	}
	c.monitor.sess = sess
	return sess, nil
}
