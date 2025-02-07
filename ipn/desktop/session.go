// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package desktop

import (
	"fmt"

	"tailscale.com/ipn/ipnauth"
)

// SessionID is a unique identifier of a desktop session.
type SessionID uint

// SessionStatus is the status of a desktop session.
type SessionStatus int

const (
	// ClosedSession is a session that does not exist, is not yet initialized by the OS,
	// or has been terminated.
	ClosedSession SessionStatus = iota
	// ForegroundSession is a session that a user can interact with,
	// such as when attached to a physical console or an active,
	// unlocked RDP connection.
	ForegroundSession
	// BackgroundSession indicates that the session is locked, disconnected,
	// or otherwise running without user presence or interaction.
	BackgroundSession
)

// String implements [fmt.Stringer].
func (s SessionStatus) String() string {
	switch s {
	case ClosedSession:
		return "Closed"
	case ForegroundSession:
		return "Foreground"
	case BackgroundSession:
		return "Background"
	default:
		panic("unreachable")
	}
}

// Session is a state of a desktop session at a given point in time.
type Session struct {
	ID     SessionID     // Identifier of the session; can be reused after the session is closed.
	Status SessionStatus // The status of the session, such as foreground or background.
	User   ipnauth.Actor // User logged into the session.
}

// Description returns a human-readable description of the session.
func (s *Session) Description() string {
	if maybeUsername, _ := s.User.Username(); maybeUsername != "" { // best effort
		return fmt.Sprintf("Session %d - %q (%s)", s.ID, maybeUsername, s.Status)
	}
	return fmt.Sprintf("Session %d (%s)", s.ID, s.Status)
}
