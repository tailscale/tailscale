package tailfs

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/net/webdav"
	"tailscale.com/safesocket"
)

type HandlerSource interface {
	Get(share string) http.Handler
}

// FileServer is a standalone WebDAV server that dynamically serves up shares.
// It's typically used in a separate process from the actual Tailfs server to
// serve up files as an unprivileged user.
type FileServer struct {
	sharePath func(string) string
	l         net.Listener
}

// NewFileServer constructs a file that looks up the filesystem path for a
// named shares using the sharePath function. If sharePath returns the empty
// string, it will return 404 Not Found.
//
// The server attempts to listen at a random address using safesocket.Listen.
// If safesocket.Listen fails, it falls back to listening on localhost.
// The listen address is available via the Addr() method.
//
// The server doesn't actually process requests until the Serve() method is
// called.
func NewFileServer(sharePath func(share string) string) (*FileServer, error) {
	path := filepath.Join(os.TempDir(), fmt.Sprintf("%v.socket", uuid.New().String()))
	l, err := safesocket.Listen(path)
	if err != nil {
		l, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
	}
	return &FileServer{
		sharePath: sharePath,
		l:         l,
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

// ServeHTTP implements the http.Handler interface.
func (s *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("ZZZZ ServeHTTP: %v", r.URL.Path)
	parts := strings.Split(r.URL.Path[1:], "/")
	r.URL.Path = "/" + strings.Join(parts[1:], "/")
	pathOnDisk := s.sharePath(parts[0])
	if pathOnDisk == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	h := &webdav.Handler{
		FileSystem: webdav.Dir(pathOnDisk),
		LockSystem: webdav.NewMemLS(),
	}
	h.ServeHTTP(w, r)
}
