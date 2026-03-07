// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailsync

import (
	"errors"
	"net/http"
	"strings"
)

// PeerURLFunc returns the PeerAPI base URL for a given peer ID (stable node ID or hostname).
type PeerURLFunc func(peerID string) string

var (
	ErrSyncNotEnabled  = errors.New("tailsync not enabled")
	ErrInvalidRootName = errors.New("root names may only contain the letters a-z, digits 0-9, underscore _, or hyphens -")
	ErrSessionExists   = errors.New("session already exists")
	ErrSessionNotFound = errors.New("session not found")
	ErrRootNotFound    = errors.New("root not found")
	ErrRootExists      = errors.New("root already exists")
)

// Service is the main tailsync service registered in tsd.System.
type Service interface {
	// SetRoot adds or updates a sync root.
	SetRoot(root *Root) error

	// RemoveRoot removes a sync root by name.
	RemoveRoot(name string) error

	// GetRoots returns all configured sync roots.
	GetRoots() []*Root

	// SetSession adds or updates a sync session.
	SetSession(session *Session) error

	// RemoveSession stops and removes a sync session.
	RemoveSession(name string) error

	// GetSessions returns all configured sessions.
	GetSessions() []*Session

	// GetSessionStatus returns the status of a named session.
	GetSessionStatus(name string) (*SessionStatus, error)

	// SetTransport configures the HTTP transport and peer URL resolver
	// used for reaching remote peers via PeerAPI.
	SetTransport(transport http.RoundTripper, peerURL PeerURLFunc)

	// ServeHTTPWithPerms handles incoming PeerAPI sync requests.
	ServeHTTPWithPerms(permissions Permissions, w http.ResponseWriter, r *http.Request)

	// Close stops all sync sessions and cleans up.
	Close() error
}

// NormalizeRootName normalizes and validates a root name.
func NormalizeRootName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !validRootName(name) {
		return "", ErrInvalidRootName
	}
	return name, nil
}

func validRootName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' {
			continue
		}
		switch r {
		case '_', '-':
			continue
		}
		return false
	}
	return true
}
