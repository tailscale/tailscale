// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package driveimpl provides an implementation of package drive.
package driveimpl

import (
	"log"
	"net"
	"net/http"
	"time"

	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl/compositedav"
	"tailscale.com/drive/driveimpl/dirfs"
	"tailscale.com/types/logger"
)

const (
	// statCacheTTL causes the local WebDAV proxy to cache file metadata to
	// avoid excessive network roundtrips. This is similar to the
	// DirectoryCacheLifetime setting of Windows' built-in SMB client,
	// see https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ff686200(v=ws.10)
	statCacheTTL = 10 * time.Second
)

// NewFileSystemForLocal starts serving a filesystem for local clients.
// Inbound connections must be handed to HandleConn.
func NewFileSystemForLocal(logf logger.Logf) *FileSystemForLocal {
	return newFileSystemForLocal(logf, &compositedav.StatCache{TTL: statCacheTTL})
}

func newFileSystemForLocal(logf logger.Logf, statCache *compositedav.StatCache) *FileSystemForLocal {
	if logf == nil {
		logf = log.Printf
	}
	fs := &FileSystemForLocal{
		logf: logf,
		h: &compositedav.Handler{
			Logf:      logf,
			StatCache: statCache,
		},
		listener: newConnListener(),
	}
	fs.startServing()
	return fs
}

// FileSystemForLocal is the Taildrive filesystem exposed to local clients. It
// provides a unified WebDAV interface to remote Taildrive shares on other nodes.
type FileSystemForLocal struct {
	logf     logger.Logf
	h        *compositedav.Handler
	listener *connListener
}

func (s *FileSystemForLocal) startServing() {
	hs := &http.Server{Handler: s.h}
	go func() {
		err := hs.Serve(s.listener)
		if err != nil {
			// TODO(oxtoacart): should we panic or something different here?
			log.Printf("serve: %v", err)
		}
	}()
}

// HandleConn handles connections from local WebDAV clients
func (s *FileSystemForLocal) HandleConn(conn net.Conn, remoteAddr net.Addr) error {
	return s.listener.HandleConn(conn, remoteAddr)
}

// SetRemotes sets the complete set of remotes on the given tailnet domain
// using a map of name -> url. If transport is specified, that transport
// will be used to connect to these remotes.
func (s *FileSystemForLocal) SetRemotes(domain string, remotes []*drive.Remote, transport http.RoundTripper) {
	children := make([]*compositedav.Child, 0, len(remotes))
	for _, remote := range remotes {
		children = append(children, &compositedav.Child{
			Child: &dirfs.Child{
				Name:      remote.Name,
				Available: remote.Available,
			},
			BaseURL:   func() (string, error) { return remote.URL(), nil },
			Transport: transport,
		})
	}

	s.h.SetChildren(domain, children...)
}

// Close() stops serving the WebDAV content
func (s *FileSystemForLocal) Close() error {
	err := s.listener.Close()
	s.h.Close()
	return err
}
