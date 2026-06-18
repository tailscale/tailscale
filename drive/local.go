// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package drive provides a filesystem that allows sharing folders between
// Tailscale nodes using WebDAV. The actual implementation of the core Taildrive
// functionality lives in package driveimpl. These packages are separated to
// allow users of Taildrive to refer to the interfaces without having a hard
// dependency on Taildrive, so that programs which don't actually use Taildrive can
// avoid its transitive dependencies.
package drive

import (
	"iter"
	"net"
	"net/http"
)

// Remote represents a remote Taildrive node.
type Remote struct {
	Name      string
	URL       func() string
	Available func() bool
}

// RemoteSource provides the current set of remote Taildrive nodes
// on demand. The drive filesystem consults Generation on each request
// and only rebuilds its internal child list when the value differs
// from the previously cached one. This lets callers avoid the
// per-netmap O(n) rebuild that an eager SetRemotes call would
// require.
//
// All methods may be called concurrently.
type RemoteSource interface {
	// Domain returns the current tailnet domain under which remotes
	// appear as sub-folders.
	Domain() string

	// Transport returns the http.RoundTripper used to reach remotes.
	Transport() http.RoundTripper

	// Remotes yields the current set of remote nodes.
	// It is called by the drive filesystem only when Generation has
	// changed since the last call.
	Remotes() iter.Seq[*Remote]

	// Generation returns a monotonically-increasing counter that
	// changes whenever the values returned by Domain, Transport, or
	// Remotes might have changed. The drive filesystem reads it on
	// every request and skips the rebuild path entirely when it
	// matches the previously-cached value.
	Generation() uint64
}

// FileSystemForLocal is the Taildrive filesystem exposed to local clients. It
// provides a unified WebDAV interface to remote Taildrive shares on other nodes.
type FileSystemForLocal interface {
	// HandleConn handles connections from local WebDAV clients
	HandleConn(conn net.Conn, remoteAddr net.Addr) error

	// SetRemoteSource sets the source from which the filesystem
	// reads the current set of remotes. The source is consulted
	// lazily on incoming WebDAV requests, so a stale cap or empty
	// tailnet costs nothing per netmap update.
	SetRemoteSource(source RemoteSource)

	// Close() stops serving the WebDAV content
	Close() error
}
