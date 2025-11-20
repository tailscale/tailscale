// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/studio-b12/gowebdav"
	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/tstest"
)

const (
	domain = `test$%domain.com`

	remote1 = `rem ote$%<>1`
	remote2 = `_rem ote$%<>2`
	share11 = `sha re$%<>11`
	share12 = `_sha re$%<>12`
	file112 = `file112.txt`
)

var (
	file111 = `fi le$%<>111.txt`
)

func init() {
	if runtime.GOOS == "windows" {
		// file with less than and greater than doesn't work on Windows
		file111 = `fi le$%111.txt`
	}
}

var (
	lockRootRegex  = regexp.MustCompile(`<D:lockroot><D:href>/?([^<]*)/?</D:href>`)
	lockTokenRegex = regexp.MustCompile(`<D:locktoken><D:href>([0-9]+)/?</D:href>`)
)

func init() {
	// set AllowShareAs() to false so that we don't try to use sub-processes
	// for access files on disk.
	drive.DisallowShareAs = true
}

// The tests in this file simulate real-life Taildrive scenarios, but without
// going over the Tailscale network stack.
func TestDirectoryListing(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.checkDirList("root directory should contain the one and only domain once a remote has been set", "/", domain)
	s.checkDirList("domain should contain its only remote", shared.Join(domain), remote1)
	s.checkDirList("remote with no shares should be empty", shared.Join(domain, remote1))

	s.addShare(remote1, share11, drive.PermissionReadWrite)
	s.checkDirList("remote with one share should contain that share", shared.Join(domain, remote1), share11)
	s.addShare(remote1, share12, drive.PermissionReadOnly)
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
	s.addShare(remote1, share11, drive.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)
	s.checkFileStatus(remote1, share11, file111)
	s.checkFileContents(remote1, share11, file111)

	s.renameFile("renaming file across shares should fail", remote1, share11, file111, share12, file112, false)

	s.renameFile("renaming file in same share should succeed", remote1, share11, file111, share11, file112, true)
	s.checkFileContents(remote1, share11, file112)

	s.addShare(remote1, share12, drive.PermissionReadOnly)
	s.writeFile("writing file to non-existent remote should fail", "non-existent", share11, file111, "hello world", false)
	s.writeFile("writing file to non-existent share should fail", remote1, "non-existent", file111, "hello world", false)
}

func TestPermissions(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.addShare(remote1, share12, drive.PermissionReadOnly)

	s.writeFile("writing file to read-only remote should fail", remote1, share12, file111, "hello world", false)
	if err := s.client.Mkdir(path.Join(remote1, share12), 0644); err == nil {
		t.Error("making directory on read-only remote should fail")
	}

	// Now, write file directly to file system so that we can test permissions
	// on other operations.
	s.write(remote1, share12, file111, "hello world")
	if err := s.client.Remove(pathTo(remote1, share12, file111)); err == nil {
		t.Error("deleting file from read-only remote should fail")
	}
	if err := s.client.Rename(pathTo(remote1, share12, file111), pathTo(remote1, share12, file112), true); err == nil {
		t.Error("moving file on read-only remote should fail")
	}
}

// TestMissingPaths verifies that the fileserver running at localhost
// correctly handles paths with missing required components.
//
// Expected path format:
// http://localhost:[PORT]/<secretToken>/<share>[/<subSharePath...>]
func TestMissingPaths(t *testing.T) {
	s := newSystem(t)

	fileserverAddr := s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	addr := strings.Split(fileserverAddr, "|")[1]
	secretToken := strings.Split(fileserverAddr, "|")[0]

	testCases := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "empty path",
			path:       "",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "single slash",
			path:       "/",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "only token",
			path:       "/" + secretToken,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "token with trailing slash",
			path:       "/" + secretToken + "/",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "token and invalid share",
			path:       "/" + secretToken + "/nonexistentshare",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := fmt.Sprintf("http://%s%s", addr, tc.path)
			resp, err := client.Get(u)
			if err != nil {
				t.Fatalf("unexpected error making request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("got status code %d, want %d", resp.StatusCode, tc.wantStatus)
			}
		})
	}
}

// TestSecretTokenAuth verifies that the fileserver running at localhost cannot
// be accessed directly without the correct secret token. This matters because
// if a victim can be induced to visit the localhost URL and access a malicious
// file on their own share, it could allow a Mark-of-the-Web bypass attack.
func TestSecretTokenAuth(t *testing.T) {
	s := newSystem(t)

	fileserverAddr := s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	addr := strings.Split(fileserverAddr, "|")[1]
	wrongSecret, err := generateSecretToken()
	if err != nil {
		t.Fatal(err)
	}
	u := fmt.Sprintf("http://%s/%s/%s", addr, wrongSecret, url.PathEscape(file111))
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected %d for incorrect secret token, but got %d", http.StatusForbidden, resp.StatusCode)
	}
}

func TestLOCK(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	u := fmt.Sprintf("http://%s/%s/%s/%s/%s",
		s.local.l.Addr(),
		url.PathEscape(domain),
		url.PathEscape(remote1),
		url.PathEscape(share11),
		url.PathEscape(file111))

	// First acquire a lock with a short timeout
	req, err := http.NewRequest("LOCK", u, strings.NewReader(lockBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Depth", "infinity")
	req.Header.Set("Timeout", "Second-1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected LOCK to succeed, but got status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	submatches := lockRootRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		t.Fatal("failed to find lockroot")
	}
	want := shared.EscapeForXML(pathTo(remote1, share11, file111))
	got := submatches[1]
	if got != want {
		t.Fatalf("want lockroot %q, got %q", want, got)
	}

	submatches = lockTokenRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		t.Fatal("failed to find locktoken")
	}
	lockToken := submatches[1]
	ifHeader := fmt.Sprintf("<%s> (<%s>)", u, lockToken)

	// Then refresh the lock with a longer timeout
	req, err = http.NewRequest("LOCK", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Depth", "infinity")
	req.Header.Set("Timeout", "Second-600")
	req.Header.Set("If", ifHeader)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected LOCK refresh to succeed, but got status %d", resp.StatusCode)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	submatches = lockRootRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		t.Fatal("failed to find lockroot after refresh")
	}
	want = shared.EscapeForXML(pathTo(remote1, share11, file111))
	got = submatches[1]
	if got != want {
		t.Fatalf("want lockroot after refresh %q, got %q", want, got)
	}

	submatches = lockTokenRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		t.Fatal("failed to find locktoken after refresh")
	}
	if submatches[1] != lockToken {
		t.Fatalf("on refresh, lock token changed from %q to %q", lockToken, submatches[1])
	}

	// Then wait past the original timeout, then try to delete without the lock
	// (should fail)
	time.Sleep(1 * time.Second)
	req, err = http.NewRequest("DELETE", u, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 423 {
		t.Fatalf("deleting without lock token should fail with 423, but got %d", resp.StatusCode)
	}

	// Then delete with the lock (should succeed)
	req, err = http.NewRequest("DELETE", u, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("If", ifHeader)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("deleting with lock token should have succeeded with 204, but got %d", resp.StatusCode)
	}
}

func TestUNLOCK(t *testing.T) {
	s := newSystem(t)

	s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	u := fmt.Sprintf("http://%s/%s/%s/%s/%s",
		s.local.l.Addr(),
		url.PathEscape(domain),
		url.PathEscape(remote1),
		url.PathEscape(share11),
		url.PathEscape(file111))

	// Acquire a lock
	req, err := http.NewRequest("LOCK", u, strings.NewReader(lockBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Depth", "infinity")
	req.Header.Set("Timeout", "Second-600")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected LOCK to succeed, but got status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	submatches := lockTokenRegex.FindStringSubmatch(string(body))
	if len(submatches) != 2 {
		t.Fatal("failed to find locktoken")
	}
	lockToken := submatches[1]

	// Release the lock
	req, err = http.NewRequest("UNLOCK", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Lock-Token", fmt.Sprintf("<%s>", lockToken))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected UNLOCK to succeed with a 204, but got status %d", resp.StatusCode)
	}

	// Then delete without the lock (should succeed)
	req, err = http.NewRequest("DELETE", u, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("deleting without lock should have succeeded with 204, but got %d", resp.StatusCode)
	}
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
	permissions map[string]drive.Permission
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

	fs := newFileSystemForLocal(log.Printf, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to Listen: %s", err)
	}
	t.Logf("FileSystemForLocal listening at %s", ln.Addr())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				t.Logf("Accept: %v", err)
				return
			}
			go fs.HandleConn(conn, conn.RemoteAddr())
		}
	}()

	client := gowebdav.NewAuthClient(fmt.Sprintf("http://%s", ln.Addr()), &noopAuthorizer{})
	client.SetTransport(&http.Transport{DisableKeepAlives: true})
	s := &system{
		t:       t,
		local:   &local{l: ln, fs: fs},
		client:  client,
		remotes: make(map[string]*remote),
	}
	t.Cleanup(s.stop)
	return s
}

func (s *system) addRemote(name string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatalf("failed to Listen: %s", err)
	}
	s.t.Logf("Remote for %v listening at %s", name, ln.Addr())

	fileServer, err := NewFileServer()
	if err != nil {
		s.t.Fatalf("failed to call NewFileServer: %s", err)
	}
	go fileServer.Serve()
	s.t.Logf("FileServer for %v listening at %s", name, fileServer.Addr())

	r := &remote{
		l:           ln,
		fileServer:  fileServer,
		fs:          NewFileSystemForRemote(log.Printf),
		shares:      make(map[string]string),
		permissions: make(map[string]drive.Permission),
	}
	r.fs.SetFileServerAddr(fileServer.Addr())
	go http.Serve(ln, r)
	s.remotes[name] = r

	remotes := make([]*drive.Remote, 0, len(s.remotes))
	for name, r := range s.remotes {
		remotes = append(remotes, &drive.Remote{
			Name: name,
			URL:  func() string { return fmt.Sprintf("http://%s", r.l.Addr()) },
		})
	}
	s.local.fs.SetRemotes(
		domain,
		remotes,
		&http.Transport{
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 5 * time.Second,
		})

	return fileServer.Addr()
}

func (s *system) addShare(remoteName, shareName string, permission drive.Permission) {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}

	f := s.t.TempDir()
	r.shares[shareName] = f
	r.permissions[shareName] = permission

	shares := make([]*drive.Share, 0, len(r.shares))
	for shareName, folder := range r.shares {
		shares = append(shares, &drive.Share{
			Name: shareName,
			Path: folder,
		})
	}
	slices.SortFunc(shares, drive.CompareShares)
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
		s.t.Fatalf("%v: expected error writing file %q, but got no error", label, path)
	}
}

func (s *system) renameFile(label, remoteName, fromShare, fromFile, toShare, toFile string, expectSuccess bool) {
	fromPath := pathTo(remoteName, fromShare, fromFile)
	toPath := pathTo(remoteName, toShare, toFile)
	err := s.client.Rename(fromPath, toPath, true)
	if expectSuccess && err != nil {
		s.t.Fatalf("%v: expected success moving file %q to %q, but got error %v", label, fromPath, toPath, err)
	} else if !expectSuccess && err == nil {
		s.t.Fatalf("%v: expected error moving file %q to %q, but got no error", label, fromPath, toPath)
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

func (s *system) write(remoteName, shareName, name, contents string) {
	filename := filepath.Join(s.remotes[remoteName].shares[shareName], name)
	err := os.WriteFile(filename, []byte(contents), 0644)
	if err != nil {
		s.t.Fatalf("failed to WriteFile: %s", err)
	}
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

const lockBody = `<?xml version="1.0" encoding="utf-8" ?>
<D:lockinfo xmlns:D='DAV:'>
  <D:lockscope><D:exclusive/></D:lockscope>
  <D:locktype><D:write/></D:locktype>
</D:lockinfo>`
