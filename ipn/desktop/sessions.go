// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package desktop

import (
	"errors"
	"runtime"
)

// ErrNotImplemented is returned by [NewSessionManager] when it is not
// implemented for the current GOOS.
var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

// SessionInitCallback is a function that is called once per [Session].
// It returns an optional cleanup function that is called when the session
// is about to be destroyed, or nil if no cleanup is needed.
// It is not safe to call SessionManager methods from within the callback.
type SessionInitCallback func(session *Session) (cleanup func())

// SessionStateCallback is a function that reports the initial or updated
// state of a [Session], such as when it transitions between foreground and background.
// It is guaranteed to be called after all registered [SessionInitCallback] functions
// have completed, and before any cleanup functions are called for the same session.
// It is not safe to call SessionManager methods from within the callback.
type SessionStateCallback func(session *Session)

// SessionManager is an interface that provides access to desktop sessions on the current platform.
// It is safe for concurrent use.
type SessionManager interface {
	// Init explicitly initializes the receiver.
	// Unless the receiver is explicitly initialized, it will be lazily initialized
	// on the first call to any other method.
	// It is safe to call Init multiple times.
	Init() error

	// Sessions returns a session snapshot taken at the time of the call.
	// Since sessions can be created or destroyed at any time, it may become
	// outdated as soon as it is returned.
	//
	// It is primarily intended for logging and debugging.
	// Prefer registering a [SessionInitCallback] or [SessionStateCallback]
	// in contexts requiring stronger guarantees.
	Sessions() (map[SessionID]*Session, error)

	// RegisterInitCallback registers a [SessionInitCallback] that is called for each existing session
	// and for each new session that is created, until the returned unregister function is called.
	// If the specified [SessionInitCallback] returns a cleanup function, it is called when the session
	// is about to be destroyed. The callback function is guaranteed to be called once and only once
	// for each existing and new session.
	RegisterInitCallback(cb SessionInitCallback) (unregister func(), err error)

	// RegisterStateCallback registers a [SessionStateCallback] that is called for each existing session
	// and every time the state of a session changes, until the returned unregister function is called.
	RegisterStateCallback(cb SessionStateCallback) (unregister func(), err error)

	// Close waits for all registered callbacks to complete
	// and releases resources associated with the receiver.
	Close() error
}
