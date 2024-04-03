// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"net"
	"net/http"
	"sync"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive/driveimpl/shared"
)

// FileServer is a standalone WebDAV server that dynamically serves up shares.
// It's typically used in a separate process from the actual Taildrive server to
// serve up files as an unprivileged user.
type FileServer struct {
	l             net.Listener
	shareHandlers map[string]http.Handler
	sharesMu      sync.RWMutex
}

// NewFileServer constructs a FileServer.
//
// The server attempts to listen at a random address on 127.0.0.1.
// The listen address is available via the Addr() method.
//
// The server has to be told about shares before it can serve them. This is
// accomplished either by calling SetShares(), or locking the shares with
// LockShares(), clearing them with ClearSharesLocked(), adding them
// individually with AddShareLocked(), and finally unlocking them with
// UnlockShares().
//
// The server doesn't actually process requests until the Serve() method is
// called.
func NewFileServer() (*FileServer, error) {
	// path := filepath.Join(os.TempDir(), fmt.Sprintf("%v.socket", uuid.New().String()))
	// l, err := safesocket.Listen(path)
	// if err != nil {
	// TODO(oxtoacart): actually get safesocket working in more environments (MacOS Sandboxed, Windows, ???)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	// }
	return &FileServer{
		l:             l,
		shareHandlers: make(map[string]http.Handler),
	}, nil
}

// Addr returns the address at which this FileServer is listening.
func (s *FileServer) Addr() string {
	return s.l.Addr().String()
}

// Serve() starts serving files and blocks until it encounters a fatal error.
func (s *FileServer) Serve() error {
	return http.Serve(s.l, s)
}

// LockShares locks the map of shares in preparation for manipulating it.
func (s *FileServer) LockShares() {
	s.sharesMu.Lock()
}

// UnlockShares unlocks the map of shares.
func (s *FileServer) UnlockShares() {
	s.sharesMu.Unlock()
}

// ClearSharesLocked clears the map of shares, assuming that LockShares() has
// been called first.
func (s *FileServer) ClearSharesLocked() {
	s.shareHandlers = make(map[string]http.Handler)
}

// AddShareLocked adds a share to the map of shares, assuming that LockShares()
// has been called first.
func (s *FileServer) AddShareLocked(share, path string) {
	s.shareHandlers[share] = &webdav.Handler{
		FileSystem: &birthTimingFS{webdav.Dir(path)},
		LockSystem: webdav.NewMemLS(),
	}
}

// SetShares sets the full map of shares to the new value, mapping name->path.
func (s *FileServer) SetShares(shares map[string]string) {
	s.LockShares()
	defer s.UnlockShares()
	s.ClearSharesLocked()
	for name, path := range shares {
		s.AddShareLocked(name, path)
	}
}

// ServeHTTP implements the http.Handler interface.
func (s *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := shared.CleanAndSplit(r.URL.Path)
	r.URL.Path = shared.Join(parts[1:]...)
	share := parts[0]
	s.sharesMu.RLock()
	h, found := s.shareHandlers[share]
	s.sharesMu.RUnlock()
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h.ServeHTTP(w, r)
}

func (s *FileServer) Close() error {
	return s.l.Close()
}
