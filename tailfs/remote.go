// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfs

import (
	"net/http"
)

var (
	// DisallowShareAs forcibly disables sharing as a specific user, only used
	// for testing.
	DisallowShareAs = false
)

// AllowShareAs reports whether sharing files as a specific user is allowed.
func AllowShareAs() bool {
	return !DisallowShareAs && doAllowShareAs()
}

// Share configures a folder to be shared through TailFS.
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

// FileSystemForRemote is the TailFS filesystem exposed to remote nodes. It
// provides a unified WebDAV interface to local directories that have been
// shared.
type FileSystemForRemote interface {
	// SetFileServerAddr sets the address of the file server to which we
	// should proxy. This is used on platforms like Windows and MacOS
	// sandboxed where we can't spawn user-specific sub-processes and instead
	// rely on the UI application that's already running as an unprivileged
	// user to access the filesystem for us.
	SetFileServerAddr(addr string)

	// SetShares sets the complete set of shares exposed by this node. If
	// AllowShareAs() reports true, we will use one subprocess per user to
	// access the filesystem (see userServer). Otherwise, we will use the file
	// server configured via SetFileServerAddr.
	SetShares(shares map[string]*Share)

	// ServeHTTPWithPerms behaves like the similar method from http.Handler but
	// also accepts a Permissions map that captures the permissions of the
	// connecting node.
	ServeHTTPWithPerms(permissions Permissions, w http.ResponseWriter, r *http.Request)

	// Close() stops serving the WebDAV content
	Close() error
}
