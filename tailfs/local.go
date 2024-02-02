// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfs

import (
	"log"
	"net"
	"net/http"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/tailfs/compositefs"
	"tailscale.com/tailfs/webdavfs"
	"tailscale.com/types/logger"
)

// Remote represents a remote Tailfs node.
type Remote struct {
	Name      string
	URL       string
	Available func() bool
}

// NewFileSystemForLocal starts serving a filesystem for local clients.
// Inbound connections must be handed to HandleConn.
func NewFileSystemForLocal(logf logger.Logf) *FileSystemForLocal {
	if logf == nil {
		logf = log.Printf
	}
	fs := &FileSystemForLocal{
		logf:     logf,
		cfs:      compositefs.New(compositefs.Options{Logf: logf}),
		listener: newConnListener(),
	}
	fs.startServing()
	return fs
}

// FileSystemForLocal is the Tailfs filesystem exposed to local clients. It
// provides a unified WebDAV interface to remote Tailfs shares on other nodes.
type FileSystemForLocal struct {
	logf     logger.Logf
	cfs      *compositefs.CompositeFileSystem
	listener *connListener
}

func (s *FileSystemForLocal) startServing() {
	hs := &http.Server{
		Handler: &webdav.Handler{
			FileSystem: s.cfs,
			LockSystem: webdav.NewMemLS(),
		},
	}
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
func (s *FileSystemForLocal) SetRemotes(domain string, remotes []*Remote, transport http.RoundTripper) {
	children := make([]*compositefs.Child, 0, len(remotes))
	for _, remote := range remotes {
		opts := webdavfs.Options{
			URL:          remote.URL,
			Transport:    transport,
			StatCacheTTL: statCacheTTL,
			Logf:         s.logf,
		}
		children = append(children, &compositefs.Child{
			Name:      remote.Name,
			FS:        webdavfs.New(opts),
			Available: remote.Available,
		})
	}

	domainChild, found := s.cfs.GetChild(domain)
	if !found {
		domainChild = compositefs.New(compositefs.Options{Logf: s.logf})
		s.cfs.SetChildren(&compositefs.Child{Name: domain, FS: domainChild})
	}
	domainChild.(*compositefs.CompositeFileSystem).SetChildren(children...)
}

// Close() stops serving the WebDAV content
func (s *FileSystemForLocal) Close() error {
	s.cfs.Close()
	return s.listener.Close()
}
