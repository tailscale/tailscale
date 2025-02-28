// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Both the desktop session manager and multi-user support
// are currently available only on Windows.
// This file does not need to be built for other platforms.

//go:build windows && !ts_omit_desktop_sessions

package ipnlocal

import (
	"cmp"
	"errors"
	"fmt"
	"sync"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/desktop"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy"
)

func init() {
	feature.Register("desktop-sessions")
	RegisterExtension("desktop-sessions", newDesktopSessionsExt)
}

// desktopSessionsExt implements [localBackendExtension].
var _ localBackendExtension = (*desktopSessionsExt)(nil)

// desktopSessionsExt extends [LocalBackend] with desktop session management.
// It keeps Tailscale running in the background if Always-On mode is enabled,
// and switches to an appropriate profile when a user signs in or out,
// locks their screen, or disconnects a remote session.
type desktopSessionsExt struct {
	logf logger.Logf
	sm   desktop.SessionManager

	*LocalBackend          // or nil, until Init is called
	cleanup       []func() // cleanup functions to call on shutdown

	// mu protects all following fields.
	// When both mu and [LocalBackend.mu] need to be taken,
	// [LocalBackend.mu] must be taken before mu.
	mu      sync.Mutex
	id2sess map[desktop.SessionID]*desktop.Session
}

// newDesktopSessionsExt returns a new [desktopSessionsExt],
// or an error if [desktop.SessionManager] is not available.
func newDesktopSessionsExt(logf logger.Logf, sys *tsd.System) (localBackendExtension, error) {
	sm, ok := sys.SessionManager.GetOK()
	if !ok {
		return nil, errors.New("session manager is not available")
	}
	return &desktopSessionsExt{logf: logf, sm: sm, id2sess: make(map[desktop.SessionID]*desktop.Session)}, nil
}

// Init implements [localBackendExtension].
func (e *desktopSessionsExt) Init(lb *LocalBackend) (err error) {
	e.LocalBackend = lb
	unregisterResolver := lb.RegisterBackgroundProfileResolver(e.getBackgroundProfile)
	unregisterSessionCb, err := e.sm.RegisterStateCallback(e.updateDesktopSessionState)
	if err != nil {
		unregisterResolver()
		return fmt.Errorf("session callback registration failed: %w", err)
	}
	e.cleanup = []func(){unregisterResolver, unregisterSessionCb}
	return nil
}

// updateDesktopSessionState is a [desktop.SessionStateCallback]
// invoked by [desktop.SessionManager] once for each existing session
// and whenever the session state changes. It updates the session map
// and switches to the best profile if necessary.
func (e *desktopSessionsExt) updateDesktopSessionState(session *desktop.Session) {
	e.mu.Lock()
	if session.Status != desktop.ClosedSession {
		e.id2sess[session.ID] = session
	} else {
		delete(e.id2sess, session.ID)
	}
	e.mu.Unlock()

	var action string
	switch session.Status {
	case desktop.ForegroundSession:
		// The user has either signed in or unlocked their session.
		// For remote sessions, this may also mean the user has connected.
		// The distinction isn't important for our purposes,
		// so let's always say "signed in".
		action = "signed in to"
	case desktop.BackgroundSession:
		action = "locked"
	case desktop.ClosedSession:
		action = "signed out from"
	default:
		panic("unreachable")
	}
	maybeUsername, _ := session.User.Username()
	userIdentifier := cmp.Or(maybeUsername, string(session.User.UserID()), "user")
	reason := fmt.Sprintf("%s %s session %v", userIdentifier, action, session.ID)

	e.SwitchToBestProfile(reason)
}

// getBackgroundProfile is a [profileResolver] that works as follows:
//
// If Always-On mode is disabled, it returns no profile ("","",false).
//
// If AlwaysOn mode is enabled, it returns the current profile unless:
// - The current user has signed out.
// - Another user has a foreground (i.e. active/unlocked) session.
//
// If the current user's session runs in the background and no other user
// has a foreground session, it returns the current profile. This applies
// when a locally signed-in user locks their screen or when a remote user
// disconnects without signing out.
//
// In all other cases, it returns no profile ("","",false).
//
// It is called with [LocalBackend.mu] locked.
func (e *desktopSessionsExt) getBackgroundProfile() (_ ipn.WindowsUserID, _ ipn.ProfileID, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if alwaysOn, _ := syspolicy.GetBoolean(syspolicy.AlwaysOn, false); !alwaysOn {
		return "", "", false
	}

	isCurrentUserSingedIn := false
	var foregroundUIDs []ipn.WindowsUserID
	for _, s := range e.id2sess {
		switch uid := s.User.UserID(); uid {
		case e.pm.CurrentUserID():
			isCurrentUserSingedIn = true
			if s.Status == desktop.ForegroundSession {
				// Keep the current profile if the user has a foreground session.
				return e.pm.CurrentUserID(), e.pm.CurrentProfile().ID(), true
			}
		default:
			if s.Status == desktop.ForegroundSession {
				foregroundUIDs = append(foregroundUIDs, uid)
			}
		}
	}

	// If there's no current user (e.g., tailscaled just started), or if the current
	// user has no foreground session, switch to the default profile of the first user
	// with a foreground session, if any.
	for _, uid := range foregroundUIDs {
		if profileID := e.pm.DefaultUserProfileID(uid); profileID != "" {
			return uid, profileID, true
		}
	}

	// If no user has a foreground session but the current user is still signed in,
	// keep the current profile even if the session is not in the foreground,
	// such as when the screen is locked or a remote session is disconnected.
	if len(foregroundUIDs) == 0 && isCurrentUserSingedIn {
		return e.pm.CurrentUserID(), e.pm.CurrentProfile().ID(), true
	}

	return "", "", false
}

// Shutdown implements [localBackendExtension].
func (e *desktopSessionsExt) Shutdown() error {
	for _, f := range e.cleanup {
		f()
	}
	e.cleanup = nil
	e.LocalBackend = nil
	return nil
}
