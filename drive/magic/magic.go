// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package magic implements the parsing and matching logic for the
// taildrive "magic" share, where the directory name itself encodes the ACL.
//
// A magic ACL directory name is a "+"-delimited list of principals. Each
// principal is either a short login (matching the local-part of a tailnet
// LoginName) or a full login email. The sharer's own login must appear in
// every directory name; a directory whose name omits the sharer is
// considered invalid and shared with no one.
package magic

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidName is returned by ParseDirACL when the directory name is empty
// or contains a malformed principal.
var ErrInvalidName = errors.New("invalid magic acl directory name")

// DirACL is a parsed magic-share directory name.
type DirACL struct {
	// Users is the deduplicated list of user specs in the directory name,
	// in the order they first appeared, normalized to lowercase.
	// Each spec is either a short login (no "@") or a full login email.
	Users []string
}

// ParseDirACL parses name as a magic ACL. Names are normalized to lowercase
// and split on "+". Returns ErrInvalidName if name is empty or contains a
// malformed principal.
func ParseDirACL(name string) (DirACL, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return DirACL{}, ErrInvalidName
	}
	parts := strings.Split(name, "+")
	users := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		if !validUserSpec(p) {
			return DirACL{}, fmt.Errorf("%w: %q", ErrInvalidName, p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		users = append(users, p)
	}
	return DirACL{Users: users}, nil
}

// validUserSpec reports whether s is a syntactically valid user spec.
// A short login is a non-empty sequence of [a-z0-9_.-]. An email is a short
// login, "@", and a non-empty sequence of [a-z0-9.-] (a hostname-ish
// fragment).
func validUserSpec(s string) bool {
	if s == "" {
		return false
	}
	local, host, hasAt := strings.Cut(s, "@")
	if local == "" {
		return false
	}
	if !validLocalPart(local) {
		return false
	}
	if !hasAt {
		return true
	}
	return validHost(host)
}

func validLocalPart(s string) bool {
	for _, r := range s {
		switch {
		case 'a' <= r && r <= 'z':
		case '0' <= r && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func validHost(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case 'a' <= r && r <= 'z':
		case '0' <= r && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// Matches reports whether peerLogin is granted access by this ACL given that
// the local node's tailnet login is sharerLogin. Both arguments are full
// LoginNames (e.g. "alice@example.com") and are matched case-insensitively.
//
// The "sharer-in-name" rule is enforced: if no principal in the ACL matches
// sharerLogin, the directory is invalid and Matches returns false for every
// peer.
func (a DirACL) Matches(peerLogin, sharerLogin string) bool {
	peerLogin = strings.ToLower(peerLogin)
	sharerLogin = strings.ToLower(sharerLogin)
	sharerOK := false
	peerOK := false
	for _, u := range a.Users {
		if matchesUser(u, sharerLogin) {
			sharerOK = true
		}
		if matchesUser(u, peerLogin) {
			peerOK = true
		}
	}
	return sharerOK && peerOK
}

// matchesUser reports whether spec matches login. spec and login are
// pre-lowercased. spec is either a short login (matched against the
// local-part of login) or a full email (matched against login as a whole).
func matchesUser(spec, login string) bool {
	if login == "" {
		return false
	}
	if strings.ContainsRune(spec, '@') {
		return spec == login
	}
	local, _, ok := strings.Cut(login, "@")
	if !ok {
		local = login
	}
	return spec == local
}
