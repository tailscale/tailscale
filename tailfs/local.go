// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailfs provides a filesystem that allows sharing folders between
// Tailscale nodes using WebDAV. The actual implementation of the core TailFS
// functionality lives in package tailfsimpl. These packages are separated to
// allow users of tailfs to refer to the interfaces without having a hard
// dependency on tailfs, so that programs which don't actually use tailfs can
// avoid its transitive dependencies.
package tailfs

import (
	"net"
	"net/http"
)

// Remote represents a remote TailFS node.
type Remote struct {
	Name      string
	URL       string
	Available func() bool
}

// FileSystemForLocal is the TailFS filesystem exposed to local clients. It
// provides a unified WebDAV interface to remote TailFS shares on other nodes.
type FileSystemForLocal interface {
	// HandleConn handles connections from local WebDAV clients
	HandleConn(conn net.Conn, remoteAddr net.Addr) error

	// SetRemotes sets the complete set of remotes on the given tailnet domain
	// using a map of name -> url. If transport is specified, that transport
	// will be used to connect to these remotes.
	SetRemotes(domain string, remotes []*Remote, transport http.RoundTripper)

	// Close() stops serving the WebDAV content
	Close() error
}
