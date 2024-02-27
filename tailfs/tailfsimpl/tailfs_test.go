// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfsimpl

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/studio-b12/gowebdav"
	"tailscale.com/tailfs"
	"tailscale.com/tailfs/tailfsimpl/shared"
	"tailscale.com/tstest"
)

const (
	domain = `test$%domain.com`

	remote1 = `remote$%1`
	remote2 = `_remote$%2`
	share11 = `share$%11`
	share12 = `_share$%12`
	file111 = `file$%111.txt`
)

func init() {
	// set AllowShareAs() to false so that we don't try to use sub-processes
	// for access files on disk.
	tailfs.DisallowShareAs = true
}

// The tests in this file simulate real-life TailFS scenarios, but without
// going over the Tailscale network stack.
func TestDirectoryListing(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.checkDirList("root directory should contain the one and only domain once a remote has been set", "/", domain)
	s.checkDirList("domain should contain its only remote", shared.Join(domain), remote1)
	s.checkDirList("remote with no shares should be empty", shared.Join(domain, remote1))

	s.addShare(remote1, share11, tailfs.PermissionReadWrite)
	s.checkDirList("remote with one share should contain that share", shared.Join(domain, remote1), share11)
	s.addShare(remote1, share12, tailfs.PermissionReadOnly)
	s.checkDirList("remote with two shares should contain both in lexicographical order", shared.Join(domain, remote1), share12, share11)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)
	s.checkDirList("remote share should contain file", shared.Join(domain, remote1, share11), file111)

	s.addRemote(remote2)
	s.checkDirList("domain with two remotes should contain both in lexicographical order", shared.Join(domain), remote2, remote1)

	s.freezeRemote(remote1)
	s.checkDirList("domain with two remotes should contain both in lexicographical order even if one is unreachable", shared.Join(domain), remote2, remote1)
	_, err := s.client.ReadDir(shared.Join(domain, remote1))
	if err == nil {
		t.Error("directory listing for offline remote should fail")
	}
	s.unfreezeRemote(remote1)

	s.checkDirList("attempt at lateral traversal should simply list shares", shared.Join(domain, remote1, share11, ".."), share12, share11)
}

func TestFileManipulation(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.addShare(remote1, share11, tailfs.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)
	s.checkFileStatus(remote1, share11, file111)
	s.checkFileContents(remote1, share11, file111)

	s.addShare(remote1, share12, tailfs.PermissionReadOnly)
	s.writeFile("writing file to read-only remote should fail", remote1, share12, file111, "hello world", false)

	s.writeFile("writing file to non-existent remote should fail", "non-existent", share11, file111, "hello world", false)
	s.writeFile("writing file to non-existent share should fail", remote1, "non-existent", file111, "hello world", false)
}

type local struct {
	l  net.Listener
	fs *FileSystemForLocal
}

type remote struct {
	l           net.Listener
	fs          *FileSystemForRemote
	fileServer  *FileServer
	shares      map[string]string
	permissions map[string]tailfs.Permission
	mu          sync.RWMutex
}

func (r *remote) freeze() {
	r.mu.Lock()
}

func (r *remote) unfreeze() {
	r.mu.Unlock()
}

func (r *remote) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.fs.ServeHTTPWithPerms(r.permissions, w, req)
}

type system struct {
	t       *testing.T
	local   *local
	client  *gowebdav.Client
	remotes map[string]*remote
}

func newSystem(t *testing.T) *system {
	// Make sure we don't leak goroutines
	tstest.ResourceCheck(t)

	fs := NewFileSystemForLocal(log.Printf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to Listen: %s", err)
	}
	t.Logf("FileSystemForLocal listening at %s", l.Addr())
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				t.Logf("Accept: %v", err)
				return
			}
			go fs.HandleConn(conn, conn.RemoteAddr())
		}
	}()

	client := gowebdav.NewAuthClient(fmt.Sprintf("http://%s", l.Addr()), &noopAuthorizer{})
	client.SetTransport(&http.Transport{DisableKeepAlives: true})
	s := &system{
		t:       t,
		local:   &local{l: l, fs: fs},
		client:  client,
		remotes: make(map[string]*remote),
	}
	t.Cleanup(s.stop)
	return s
}

func (s *system) addRemote(name string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatalf("failed to Listen: %s", err)
	}
	s.t.Logf("Remote for %v listening at %s", name, l.Addr())

	fileServer, err := NewFileServer()
	if err != nil {
		s.t.Fatalf("failed to call NewFileServer: %s", err)
	}
	go fileServer.Serve()
	s.t.Logf("FileServer for %v listening at %s", name, fileServer.Addr())

	r := &remote{
		l:           l,
		fileServer:  fileServer,
		fs:          NewFileSystemForRemote(log.Printf),
		shares:      make(map[string]string),
		permissions: make(map[string]tailfs.Permission),
	}
	r.fs.SetFileServerAddr(fileServer.Addr())
	go http.Serve(l, r)
	s.remotes[name] = r

	remotes := make([]*tailfs.Remote, 0, len(s.remotes))
	for name, r := range s.remotes {
		remotes = append(remotes, &tailfs.Remote{
			Name: name,
			URL:  fmt.Sprintf("http://%s", r.l.Addr()),
		})
	}
	s.local.fs.SetRemotes(
		domain,
		remotes,
		&http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 5 * time.Second,
		})
}

func (s *system) addShare(remoteName, shareName string, permission tailfs.Permission) {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}

	f := s.t.TempDir()
	r.shares[shareName] = f
	r.permissions[shareName] = permission

	shares := make(map[string]*tailfs.Share, len(r.shares))
	for shareName, folder := range r.shares {
		shares[shareName] = &tailfs.Share{
			Name: shareName,
			Path: folder,
		}
	}
	r.fs.SetShares(shares)
	r.fileServer.SetShares(r.shares)
}

func (s *system) freezeRemote(remoteName string) {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}
	r.freeze()
}

func (s *system) unfreezeRemote(remoteName string) {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}
	r.unfreeze()
}

func (s *system) writeFile(label, remoteName, shareName, name, contents string, expectSuccess bool) {
	path := pathTo(remoteName, shareName, name)
	err := s.client.Write(path, []byte(contents), 0644)
	if expectSuccess && err != nil {
		s.t.Fatalf("%v: expected success writing file %q, but got error %v", label, path, err)
	} else if !expectSuccess && err == nil {
		s.t.Fatalf("%v: expected error writing file %q", label, path)
	}
}

func (s *system) checkFileStatus(remoteName, shareName, name string) {
	expectedFI := s.stat(remoteName, shareName, name)
	actualFI := s.statViaWebDAV(remoteName, shareName, name)
	s.checkFileInfosEqual(expectedFI, actualFI, fmt.Sprintf("%s/%s/%s should show same FileInfo via WebDAV stat as local stat", remoteName, shareName, name))
}

func (s *system) checkFileContents(remoteName, shareName, name string) {
	expected := s.read(remoteName, shareName, name)
	actual := s.readViaWebDAV(remoteName, shareName, name)
	if expected != actual {
		s.t.Errorf("%s/%s/%s should show same contents via WebDAV read as local read\nwant: %q\nhave: %q", remoteName, shareName, name, expected, actual)
	}
}

func (s *system) checkDirList(label string, path string, want ...string) {
	got, err := s.client.ReadDir(path)
	if err != nil {
		s.t.Fatalf("failed to Readdir: %s", err)
	}

	if len(want) == 0 && len(got) == 0 {
		return
	}

	gotNames := make([]string, 0, len(got))
	for _, fi := range got {
		gotNames = append(gotNames, fi.Name())
	}
	if diff := cmp.Diff(want, gotNames); diff != "" {
		s.t.Errorf("%v: (-got, +want):\n%s", label, diff)
	}
}

func (s *system) stat(remoteName, shareName, name string) os.FileInfo {
	filename := filepath.Join(s.remotes[remoteName].shares[shareName], name)
	fi, err := os.Stat(filename)
	if err != nil {
		s.t.Fatalf("failed to Stat: %s", err)
	}

	return fi
}

func (s *system) statViaWebDAV(remoteName, shareName, name string) os.FileInfo {
	path := pathTo(remoteName, shareName, name)
	fi, err := s.client.Stat(path)
	if err != nil {
		s.t.Fatalf("failed to Stat: %s", err)
	}

	return fi
}

func (s *system) read(remoteName, shareName, name string) string {
	filename := filepath.Join(s.remotes[remoteName].shares[shareName], name)
	b, err := os.ReadFile(filename)
	if err != nil {
		s.t.Fatalf("failed to ReadFile: %s", err)
	}

	return string(b)
}

func (s *system) readViaWebDAV(remoteName, shareName, name string) string {
	path := pathTo(remoteName, shareName, name)
	b, err := s.client.Read(path)
	if err != nil {
		s.t.Fatalf("failed to OpenFile: %s", err)
	}
	return string(b)
}

func (s *system) stop() {
	err := s.local.fs.Close()
	if err != nil {
		s.t.Fatalf("failed to Close fs: %s", err)
	}

	err = s.local.l.Close()
	if err != nil {
		s.t.Fatalf("failed to Close listener: %s", err)
	}

	for _, r := range s.remotes {
		err = r.fs.Close()
		if err != nil {
			s.t.Fatalf("failed to Close remote fs: %s", err)
		}

		err = r.l.Close()
		if err != nil {
			s.t.Fatalf("failed to Close remote listener: %s", err)
		}

		err = r.fileServer.Close()
		if err != nil {
			s.t.Fatalf("failed to Close remote fileserver: %s", err)
		}
	}
}

func (s *system) checkFileInfosEqual(expected, actual fs.FileInfo, label string) {
	if expected == nil && actual == nil {
		return
	}
	diff := cmp.Diff(fileInfoToStatic(expected, true), fileInfoToStatic(actual, false))
	if diff != "" {
		s.t.Errorf("%v (-got, +want):\n%s", label, diff)
	}
}

func fileInfoToStatic(fi fs.FileInfo, fixupMode bool) fs.FileInfo {
	mode := fi.Mode()
	if fixupMode {
		// WebDAV doesn't transmit file modes, so we just mimic the defaults that
		// our WebDAV client uses.
		mode = os.FileMode(0664)
		if fi.IsDir() {
			mode = 0775 | os.ModeDir
		}
	}
	return &shared.StaticFileInfo{
		Named:      fi.Name(),
		Sized:      fi.Size(),
		Moded:      mode,
		ModdedTime: fi.ModTime().Truncate(1 * time.Second).UTC(),
		Dir:        fi.IsDir(),
	}
}

func pathTo(remote, share, name string) string {
	return path.Join(domain, remote, share, name)
}

// noopAuthorizer implements gowebdav.Authorizer. It does no actual
// authorizing. We use it in place of gowebdav's built-in authorizer in order
// to avoid a race condition in that authorizer.
type noopAuthorizer struct{}

func (a *noopAuthorizer) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &noopAuthenticator{}, nil
}

func (a *noopAuthorizer) AddAuthenticator(key string, fn gowebdav.AuthFactory) {
}

type noopAuthenticator struct{}

func (a *noopAuthenticator) Authorize(c *http.Client, rq *http.Request, path string) error {
	return nil
}

func (a *noopAuthenticator) Verify(c *http.Client, rs *http.Response, path string) (redo bool, err error) {
	return false, nil
}

func (a *noopAuthenticator) Clone() gowebdav.Authenticator {
	return &noopAuthenticator{}
}

func (a *noopAuthenticator) Close() error {
	return nil
}
