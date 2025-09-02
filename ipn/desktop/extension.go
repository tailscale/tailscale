// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Both the desktop session manager and multi-user support
// are currently available only on Windows.
// This file does not need to be built for other platforms.

//go:build windows && !ts_omit_desktop_sessions

package desktop

import (
	"cmp"
	"fmt"
	"sync"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

// featureName is the name of the feature implemented by this package.
// It is also the the [desktopSessionsExt] name and the log prefix.
const featureName = "desktop-sessions"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newDesktopSessionsExt)
}

// [desktopSessionsExt] implements [ipnext.Extension].
var _ ipnext.Extension = (*desktopSessionsExt)(nil)

// desktopSessionsExt extends [LocalBackend] with desktop session management.
// It keeps Tailscale running in the background if Always-On mode is enabled,
// and switches to an appropriate profile when a user signs in or out,
// locks their screen, or disconnects a remote session.
type desktopSessionsExt struct {
	logf logger.Logf
	sm   SessionManager

	host    ipnext.Host // or nil, until Init is called
	cleanup []func()    // cleanup functions to call on shutdown

	// mu protects all following fields.
	mu       sync.Mutex
	sessByID map[SessionID]*Session
}

// newDesktopSessionsExt returns a new [desktopSessionsExt],
// or an error if a [SessionManager] cannot be created.
// It is registered with [ipnext.RegisterExtension] if the package is imported.
func newDesktopSessionsExt(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	logf = logger.WithPrefix(logf, featureName+": ")
	sm, err := NewSessionManager(logf)
	if err != nil {
		return nil, fmt.Errorf("%w: session manager is not available: %w", ipnext.SkipExtension, err)
	}
	return &desktopSessionsExt{
		logf:     logf,
		sm:       sm,
		sessByID: make(map[SessionID]*Session),
	}, nil
}

// Name implements [ipnext.Extension].
func (e *desktopSessionsExt) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *desktopSessionsExt) Init(host ipnext.Host) (err error) {
	e.host = host
	unregisterSessionCb, err := e.sm.RegisterStateCallback(e.updateDesktopSessionState)
	if err != nil {
		return fmt.Errorf("session callback registration failed: %w", err)
	}
	host.Hooks().BackgroundProfileResolvers.Add(e.getBackgroundProfile)
	e.cleanup = []func(){unregisterSessionCb}
	return nil
}

// updateDesktopSessionState is a [SessionStateCallback]
// invoked by [SessionManager] once for each existing session
// and whenever the session state changes. It updates the session map
// and switches to the best profile if necessary.
func (e *desktopSessionsExt) updateDesktopSessionState(session *Session) {
	e.mu.Lock()
	if session.Status != ClosedSession {
		e.sessByID[session.ID] = session
	} else {
		delete(e.sessByID, session.ID)
	}
	e.mu.Unlock()

	var action string
	switch session.Status {
	case ForegroundSession:
		// The user has either signed in or unlocked their session.
		// For remote sessions, this may also mean the user has connected.
		// The distinction isn't important for our purposes,
		// so let's always say "signed in".
		action = "signed in to"
	case BackgroundSession:
		action = "locked"
	case ClosedSession:
		action = "signed out from"
	default:
		panic("unreachable")
	}
	maybeUsername, _ := session.User.Username()
	userIdentifier := cmp.Or(maybeUsername, string(session.User.UserID()), "user")
	reason := fmt.Sprintf("%s %s session %v", userIdentifier, action, session.ID)

	e.host.Profiles().SwitchToBestProfileAsync(reason)
}

// getBackgroundProfile is a [ipnext.ProfileResolver] that works as follows:
//
// If Always-On mode is disabled, it returns no profile.
//
// If AlwaysOn mode is enabled, it returns the current profile unless:
// - The current profile's owner has signed out.
// - Another user has a foreground (i.e. active/unlocked) session.
//
// If the current profile owner's session runs in the background and no other user
// has a foreground session, it returns the current profile. This applies
// when a locally signed-in user locks their screen or when a remote user
// disconnects without signing out.
//
// In all other cases, it returns no profile.
func (e *desktopSessionsExt) getBackgroundProfile(profiles ipnext.ProfileStore) ipn.LoginProfileView {
	e.mu.Lock()
	defer e.mu.Unlock()

	if alwaysOn, _ := policyclient.Get().GetBoolean(pkey.AlwaysOn, false); !alwaysOn {
		// If the Always-On mode is disabled, there's no background profile
		// as far as the desktop session extension is concerned.
		return ipn.LoginProfileView{}
	}

	isCurrentProfileOwnerSignedIn := false
	var foregroundUIDs []ipn.WindowsUserID
	for _, s := range e.sessByID {
		switch uid := s.User.UserID(); uid {
		case profiles.CurrentProfile().LocalUserID():
			isCurrentProfileOwnerSignedIn = true
			if s.Status == ForegroundSession {
				// Keep the current profile if the user has a foreground session.
				return profiles.CurrentProfile()
			}
		default:
			if s.Status == ForegroundSession {
				foregroundUIDs = append(foregroundUIDs, uid)
			}
		}
	}

	// If the current profile is empty and not owned by anyone (e.g., tailscaled just started),
	// or if the current profile's owner has no foreground session, switch to the default profile
	// of the first user with a foreground session, if any.
	for _, uid := range foregroundUIDs {
		if profile := profiles.DefaultUserProfile(uid); profile.ID() != "" {
			return profile
		}
	}

	// If no user has a foreground session but the current profile's owner is still signed in,
	// keep the current profile even if the session is not in the foreground,
	// such as when the screen is locked or a remote session is disconnected.
	if len(foregroundUIDs) == 0 && isCurrentProfileOwnerSignedIn {
		return profiles.CurrentProfile()
	}

	// Otherwise, there's no background profile.
	return ipn.LoginProfileView{}
}

// Shutdown implements [ipnext.Extension].
func (e *desktopSessionsExt) Shutdown() error {
	for _, f := range e.cleanup {
		f()
	}
	e.cleanup = nil
	e.host = nil
	return e.sm.Close()
}
