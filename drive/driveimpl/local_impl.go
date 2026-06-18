// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package driveimpl provides an implementation of package drive.
package driveimpl

import (
	"log"
	"net"
	"net/http"
	"sync"
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

	// sourceMu guards source and cachedGen. It also serializes the
	// rebuild path so concurrent requests don't race to replace
	// children with stale data.
	sourceMu  sync.Mutex
	source    drive.RemoteSource
	cachedGen uint64
	haveGen   bool // true once cachedGen reflects an actual source.Generation call
}

func (s *FileSystemForLocal) startServing() {
	hs := &http.Server{Handler: http.HandlerFunc(s.serveHTTP)}
	go func() {
		err := hs.Serve(s.listener)
		if err != nil {
			// TODO(oxtoacart): should we panic or something different here?
			log.Printf("serve: %v", err)
		}
	}()
}

// serveHTTP refreshes the underlying compositedav children from the
// remote source if its generation has changed, then delegates to the
// composite handler. The refresh path is skipped entirely when the
// generation is unchanged, which is the common case.
func (s *FileSystemForLocal) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.refresh()
	s.h.ServeHTTP(w, r)
}

// refresh rebuilds the compositedav children from the current source
// if its generation has changed since the last refresh. It is a no-op
// when no source is set or when the generation matches the cached
// value.
func (s *FileSystemForLocal) refresh() {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()

	source := s.source
	if source == nil {
		return
	}
	gen := source.Generation()
	if s.haveGen && gen == s.cachedGen {
		return
	}

	transport := source.Transport()
	var children []*compositedav.Child
	for remote := range source.Remotes() {
		children = append(children, &compositedav.Child{
			Child: &dirfs.Child{
				Name:      remote.Name,
				Available: remote.Available,
			},
			BaseURL:   func() (string, error) { return remote.URL(), nil },
			Transport: transport,
		})
	}
	s.h.SetChildren(source.Domain(), children...)
	s.cachedGen = gen
	s.haveGen = true
}

// HandleConn handles connections from local WebDAV clients
func (s *FileSystemForLocal) HandleConn(conn net.Conn, remoteAddr net.Addr) error {
	return s.listener.HandleConn(conn, remoteAddr)
}

// SetRemoteSource sets the source from which the filesystem reads the
// current set of remotes. It replaces any previously set source and
// forces a rebuild on the next incoming request.
func (s *FileSystemForLocal) SetRemoteSource(source drive.RemoteSource) {
	s.sourceMu.Lock()
	s.source = source
	s.cachedGen = 0
	s.haveGen = false
	s.sourceMu.Unlock()
}

// Close() stops serving the WebDAV content
func (s *FileSystemForLocal) Close() error {
	err := s.listener.Close()
	s.h.Close()
	return err
}
