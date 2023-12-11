// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package tailfs provides a filesystem that allows sharing folders between
// Tailscale nodes using WebDAV.
package tailfs

import (
	"log"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/tailscale/gowebdav"
	"golang.org/x/net/webdav"
	"tailscale.com/connlistener"
	"tailscale.com/tailcfg"
	"tailscale.com/tailfs/compositefs"
	"tailscale.com/tailfs/webdavfs"
	"tailscale.com/types/logger"
)

const (
	// statCacheTTL causes the local WebDAV proxy to cache file metadata to
	// avoid excessive network roundtrips. This is similar to the
	// DirectoryCacheLifetime setting of Windows' build-in SMB client,
	// see https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ff686200(v=ws.10)
	statCacheTTL = 10 * time.Second
)

// Share represents a folder that's shared with remote Tailfs nodes.
type Share struct {
	// Name is how this share appears on remote nodes.
	Name string `json:"name"`
	// Path is the path to the directory on this machine that's being shared.
	Path string `json:"path"`
	// Who is the UNIX or Windows username of the local account that owns this
	// share. File read/write permissions are enforced based on this username.
	Who string `json:"who"`
	// Readers is a list of Tailscale principals that are allowed to read this
	// share.
	Readers []string `json:"readers,omitempty"`
	// Writers is a list of Tailscale principals that are allowed to write to
	// this share.
	Writers []string `json:"writers,omitempty"`
}

// Principal represents a person or machine attempting to access a share.
type Principal struct {
	IsSelf bool
	UID    tailcfg.UserID
	Groups []string
}

type Handler interface {
	// ServeHTTP is like the equivalent method from http.Handler but also
	// accepts a Principal identifying the user making the request.
	ServeHTTP(principal *Principal, w http.ResponseWriter, r *http.Request)
}

// FileSystem encapsulates a TailFS filesystem. TailFS provides a WebDAV
// interface to a unified view of local directories and/or remote WebDAV
// shares.
type FileSystem interface {
	// HandleConn handles connections from local WebDAV clients
	HandleConn(conn net.Conn, remoteAddr net.Addr) error

	// Handler() returns an http.Handler that can be used to serve tailfs to
	Handler() http.Handler

	// AddShare adds a named share on the local filesystem
	AddShare(name, path string)

	// Remove removes a named share
	RemoveShare(name string)

	// SetRemotes sets the complete set of remotes on the given tailnet domain
	// using a map of name -> url. If transport is specified, that transport
	// will be used to connect to these remotes.
	SetRemotes(domain string, namesToURLS map[string]string, transport http.RoundTripper)

	// Close() stops serving the WebDAV content
	Close() error
}

// ListenAndServe starts serving a filesystem to WebDAV clients at the
// specified addr, returning the FileSystem and the actual addr that
// it's listening on.
func ListenAndServe(addr string, logf logger.Logf) (FileSystem, string, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	fs := Serve(logf)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				return
			}
			err = fs.HandleConn(conn, conn.RemoteAddr())
			if err != nil {
				log.Printf("HandleConn: %v", err)
			}
		}
	}()
	return fs, l.Addr().String(), nil
}

// Serve starts serving a filesystem that handles connections explicitly passed
// to HandleConn().
func Serve(logf logger.Logf) FileSystem {
	fs := &fileSystem{logf: logf}
	fs.serveAt()
	return fs
}

type fileSystem struct {
	logf     logger.Logf
	cfs      compositefs.CompositeFileSystem
	listener connlistener.Listener
	handler  http.Handler
}

func (s *fileSystem) serveAt() {
	s.cfs = compositefs.New(s.logf)
	s.handler = &webdav.Handler{
		FileSystem: s.cfs,
		LockSystem: webdav.NewMemLS(),
	}

	s.listener = connlistener.New()

	hs := &http.Server{Handler: s.handler}
	go func() {
		err := hs.Serve(s.listener)
		if err != nil {
			// TODO(oxtoacart): should we panic or something different here?
			log.Printf("serve: %v", err)
		}
	}()
}

func (s *fileSystem) HandleConn(conn net.Conn, remoteAddr net.Addr) error {
	return s.listener.HandleConn(conn, remoteAddr)
}

func (s *fileSystem) Handler() http.Handler {
	return s.handler
}

func (s *fileSystem) AddShare(name, path string) {
	s.cfs.AddChild(name, webdav.Dir(path))
}

func (s *fileSystem) RemoveShare(name string) {
	s.cfs.RemoveChild(name)
}

func (s *fileSystem) SetRemotes(domain string, namesToURLS map[string]string, transport http.RoundTripper) {
	remotes := make(map[string]webdav.FileSystem, len(namesToURLS))
	for name, url := range namesToURLS {
		client := gowebdav.New(&gowebdav.Opts{
			URI:       url,
			Transport: transport,
		})
		s.logf("ZZZZ setting transport for %v to %v", domain, reflect.TypeOf(transport))
		client.SetTransport(transport)
		opts := &webdavfs.Opts{
			Client:       client,
			StatCacheTTL: statCacheTTL,
			Logf:         s.logf,
		}
		remotes[name] = webdavfs.New(opts)
	}

	domainChild, found := s.cfs.GetChild(domain)
	if !found {
		domainChild = compositefs.New(s.logf)
		s.cfs.SetChildren(map[string]webdav.FileSystem{domain: domainChild})
	}
	domainChild.(compositefs.CompositeFileSystem).SetChildren(remotes)
}

func (s *fileSystem) RemoveRemote(name string) {
	s.cfs.RemoveChild(name)
}

func (s *fileSystem) Close() error {
	return s.listener.Close()
}
