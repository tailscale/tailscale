// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfs

import (
	"log"
	"net"
	"net/http"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/connlistener"
	"tailscale.com/tailfs/compositefs"
	"tailscale.com/tailfs/webdavfs"
	"tailscale.com/types/logger"
)

// Remote represents a remote TailFS node.
type Remote struct {
	Name      string
	URL       string
	Available func() bool
}

// ForLocal is the TailFS filesystem exposed to local clients. It provides a
// unified WebDAV interface to remote TailFS shares on other nodes.
type ForLocal interface {
	// SetRemotes sets the complete set of remotes on the given tailnet domain
	// using a map of name -> url. If transport is specified, that transport
	// will be used to connect to these remotes.
	SetRemotes(domain string, remotes []*Remote, transport http.RoundTripper)

	// HandleConn handles connections from local WebDAV clients
	HandleConn(conn net.Conn, remoteAddr net.Addr) error

	// Close() stops serving the WebDAV content
	Close() error
}

// NewFileSystemForLocal starts serving a filesystem for local clients.
// Inbound connections must be handed to HandleConn.
func NewFileSystemForLocal(logf logger.Logf) ForLocal {
	fs := &fileSystemForLocal{
		logf:     logf,
		cfs:      compositefs.New(&compositefs.Opts{Logf: logf}),
		listener: connlistener.New(),
	}
	fs.startServing()
	return fs
}

type fileSystemForLocal struct {
	logf     logger.Logf
	cfs      compositefs.CompositeFileSystem
	listener connlistener.Listener
}

func (s *fileSystemForLocal) startServing() {
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

func (s *fileSystemForLocal) HandleConn(conn net.Conn, remoteAddr net.Addr) error {
	return s.listener.HandleConn(conn, remoteAddr)
}

func (s *fileSystemForLocal) SetRemotes(domain string, remotes []*Remote, transport http.RoundTripper) {
	children := make([]*compositefs.Child, 0, len(remotes))
	for _, remote := range remotes {
		opts := &webdavfs.Opts{
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
		domainChild = compositefs.New(&compositefs.Opts{Logf: s.logf})
		s.cfs.SetChildren(&compositefs.Child{Name: domain, FS: domainChild})
	}
	domainChild.(compositefs.CompositeFileSystem).SetChildren(children...)
}

func (s *fileSystemForLocal) Close() error {
	s.cfs.Close()
	return s.listener.Close()
}
