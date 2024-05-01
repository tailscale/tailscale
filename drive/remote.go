// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package drive

//go:generate go run tailscale.com/cmd/viewer --type=Share --clonefunc

import (
	"bytes"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var (
	// DisallowShareAs forcibly disables sharing as a specific user, only used
	// for testing.
	DisallowShareAs     = false
	ErrDriveNotEnabled  = errors.New("Taildrive not enabled")
	ErrInvalidShareName = errors.New("Share names may only contain the letters a-z, underscore _, parentheses (), or spaces")
)

var (
	shareNameRegex = regexp.MustCompile(`^[a-z0-9_\(\) ]+$`)
)

// AllowShareAs reports whether sharing files as a specific user is allowed.
func AllowShareAs() bool {
	return !DisallowShareAs && doAllowShareAs()
}

// Share configures a folder to be shared through drive.
type Share struct {
	// Name is how this share appears on remote nodes.
	Name string `json:"name,omitempty"`

	// Path is the path to the directory on this machine that's being shared.
	Path string `json:"path,omitempty"`

	// As is the UNIX or Windows username of the local account used for this
	// share. File read/write permissions are enforced based on this username.
	// Can be left blank to use the default value of "whoever is running the
	// Tailscale GUI".
	As string `json:"who,omitempty"`

	// BookmarkData contains security-scoped bookmark data for the Sandboxed
	// Mac application. The Sandboxed Mac application gains permission to
	// access the Share's folder as a result of a user selecting it in a file
	// picker. In order to retain access to it across restarts, it needs to
	// hold on to a security-scoped bookmark. That bookmark is stored here. See
	// https://developer.apple.com/documentation/security/app_sandbox/accessing_files_from_the_macos_app_sandbox#4144043
	BookmarkData []byte `json:"bookmarkData,omitempty"`
}

func ShareViewsEqual(a, b ShareView) bool {
	if !a.Valid() && !b.Valid() {
		return true
	}
	if !a.Valid() || !b.Valid() {
		return false
	}
	return a.Name() == b.Name() && a.Path() == b.Path() && a.As() == b.As() && a.BookmarkData().Equal(b.ж.BookmarkData)
}

func SharesEqual(a, b *Share) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Name == b.Name && a.Path == b.Path && a.As == b.As && bytes.Equal(a.BookmarkData, b.BookmarkData)
}

func CompareShares(a, b *Share) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return strings.Compare(a.Name, b.Name)
}

// FileSystemForRemote is the drive filesystem exposed to remote nodes. It
// provides a unified WebDAV interface to local directories that have been
// shared.
type FileSystemForRemote interface {
	// SetFileServerAddr sets the address of the file server to which we
	// should proxy. This is used on platforms like Windows and MacOS
	// sandboxed where we can't spawn user-specific sub-processes and instead
	// rely on the UI application that's already running as an unprivileged
	// user to access the filesystem for us.
	//
	// Note that this includes both the file server's secret token and its
	// address, delimited by a pipe |.
	SetFileServerAddr(addr string)

	// SetShares sets the complete set of shares exposed by this node. If
	// AllowShareAs() reports true, we will use one subprocess per user to
	// access the filesystem (see userServer). Otherwise, we will use the file
	// server configured via SetFileServerAddr.
	SetShares(shares []*Share)

	// ServeHTTPWithPerms behaves like the similar method from http.Handler but
	// also accepts a Permissions map that captures the permissions of the
	// connecting node.
	ServeHTTPWithPerms(permissions Permissions, w http.ResponseWriter, r *http.Request)

	// Close() stops serving the WebDAV content
	Close() error
}

// NormalizeShareName normalizes the given share name and returns an error if
// it contains any disallowed characters.
func NormalizeShareName(name string) (string, error) {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	name = strings.ToLower(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	if !shareNameRegex.MatchString(name) {
		return "", ErrInvalidShareName
	}

	return name, nil
}
