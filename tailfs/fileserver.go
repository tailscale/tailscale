package tailfs

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/webdav"
)

// FileServer is a standalone WebDAV server that dynamically serves up shares.
// It's typically used in a separate process from the actual Tailfs server to
// serve up files as an unprivileged user.
type FileServer struct {
	l        net.Listener
	shares   map[string]string
	sharesMx sync.RWMutex
}

// NewFileServer constructs a FileServer.
//
// The server attempts to listen at a random address using safesocket.Listen.
// If safesocket.Listen fails, it falls back to listening on localhost.
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
		l:      l,
		shares: make(map[string]string),
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

func (s *FileServer) LockShares() {
	s.sharesMx.Lock()
}

func (s *FileServer) UnlockShares() {
	s.sharesMx.Unlock()
}

func (s *FileServer) ClearSharesLocked() {
	s.shares = make(map[string]string)
}

func (s *FileServer) AddShareLocked(share, path string) {
	s.shares[share] = path
}

func (s *FileServer) SetShares(shares map[string]string) {
	s.sharesMx.Lock()
	defer s.sharesMx.Unlock()
	s.shares = shares
}

// ServeHTTP implements the http.Handler interface.
func (s *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("ZZZZ ServeHTTP: %v", r.URL.Path)
	parts := strings.Split(r.URL.Path[1:], "/")
	r.URL.Path = "/" + strings.Join(parts[1:], "/")
	s.sharesMx.RLock()
	pathOnDisk, found := s.shares[parts[0]]
	s.sharesMx.RUnlock()
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h := &webdav.Handler{
		FileSystem: webdav.Dir(pathOnDisk),
		LockSystem: webdav.NewMemLS(),
	}
	h.ServeHTTP(w, r)
}
