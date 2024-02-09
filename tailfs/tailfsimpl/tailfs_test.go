// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfsimpl

import (
	"context"
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
	"github.com/tailscale/xnet/webdav"
	"tailscale.com/tailfs"
	"tailscale.com/tailfs/tailfsimpl/shared"
	"tailscale.com/tailfs/tailfsimpl/webdavfs"
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
	defer s.stop()

	s.addRemote(remote1)
	s.checkDirList("root directory should contain the one and only domain once a remote has been set", "/", domain)
	s.checkDirList("domain should contain its only remote", shared.Join(domain), remote1)
	s.checkDirList("remote with no shares should be empty", shared.Join(domain, remote1))
	s.addShare(remote1, share11, tailfs.PermissionReadWrite)
	s.checkDirList("remote with one share should contain that share", shared.Join(domain, remote1), share11)
	s.addShare(remote1, share12, tailfs.PermissionReadOnly)
	s.checkDirList("remote with two shares should contain both in lexicographical order", shared.Join(domain, remote1), share12, share11)
	s.checkDirListIncremental("remote with two shares should contain both in lexicographical order even when reading directory incrementally", shared.Join(domain, remote1), share12, share11)

	s.addRemote(remote2)
	s.checkDirList("domain with two remotes should contain both in lexicographical order", shared.Join(domain), remote2, remote1)

	s.freezeRemote(remote1)
	s.checkDirList("domain with two remotes should contain both in lexicographical order even if one is unreachable", shared.Join(domain), remote2, remote1)
	s.checkDirList("directory listing for offline remote should return empty list", shared.Join(domain, remote1))
	s.unfreezeRemote(remote1)

	s.checkDirList("attempt at lateral traversal should simply list shares", shared.Join(domain, remote1, share11, ".."), share12, share11)
}

func TestFileManipulation(t *testing.T) {
	s := newSystem(t)
	defer s.stop()

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

func TestFileOps(t *testing.T) {
	ctx := context.Background()

	s := newSystem(t)
	defer s.stop()

	s.addRemote(remote1)
	s.addShare(remote1, share11, tailfs.PermissionReadWrite)
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, "hello world", true)
	fi, err := s.fs.Stat(context.Background(), pathTo(remote1, share11, file111))
	if err != nil {
		t.Fatalf("failed to Stat: %s", err)
	}
	bt, ok := fi.(webdav.BirthTimer)
	if !ok {
		t.Fatal("FileInfo should be a BirthTimer")
	}
	birthTime, err := bt.BirthTime(ctx)
	if err != nil {
		t.Fatalf("failed to BirthTime: %s", err)
	}
	if birthTime.IsZero() {
		t.Fatal("BirthTime() should return a non-zero time")
	}

	_, err = s.fs.OpenFile(ctx, pathTo(remote1, share11, "nonexistent.txt"), os.O_RDONLY, 0)
	if err == nil {
		t.Fatal("opening non-existent file for read should fail")
	}

	dir, err := s.fs.OpenFile(ctx, shared.Join(domain, remote1), os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open directory for read: %s", err)
	}
	defer dir.Close()

	_, err = dir.Seek(0, io.SeekStart)
	if err == nil {
		t.Fatal("seeking in directory should fail")
	}

	_, err = dir.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("reading bytes from directory should fail")
	}
	_, err = dir.Write(make([]byte, 8))
	if err == nil {
		t.Fatal("writing bytes to directory should fail")
	}

	readOnlyFile, err := s.fs.OpenFile(ctx, pathTo(remote1, share11, file111), os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open file for read: %s", err)
	}
	defer readOnlyFile.Close()

	n, err := readOnlyFile.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("failed to seek 0 from start of read-only file: %s", err)
	}
	if n != 0 {
		t.Fatal("seeking 0 from start of read-only file should return 0")
	}

	n, err = readOnlyFile.Seek(1, io.SeekStart)
	if err != nil {
		t.Fatalf("failed to seek 1 from start of read-only file: %s", err)
	}
	if n != 1 {
		t.Fatal("seeking 1 from start of read-only file should return 1")
	}

	n, err = readOnlyFile.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("failed to seek 0 from end of read-only file: %s", err)
	}
	if n != fi.Size() {
		t.Fatal("seeking 0 from end of read-only file should return file size")
	}

	_, err = readOnlyFile.Seek(1, io.SeekEnd)
	if err == nil {
		t.Fatal("seeking 1 from end of read-only file should fail")
	}

	_, err = readOnlyFile.Seek(0, io.SeekCurrent)
	if err == nil {
		t.Fatal("seeking from current of read-only file should fail")
	}

	_, err = readOnlyFile.Write(make([]byte, 8))
	if err == nil {
		t.Fatal("writing bytes to read-only file should fail")
	}

	writeOnlyFile, err := s.fs.OpenFile(ctx, pathTo(remote1, share11, file111), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("failed to OpenFile for write: %s", err)
	}
	defer writeOnlyFile.Close()

	_, err = writeOnlyFile.Seek(0, io.SeekStart)
	if err == nil {
		t.Fatal("seeking in write only file should fail")
	}

	_, err = writeOnlyFile.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("reading bytes from a write only file should fail")
	}
}

func TestFileRewind(t *testing.T) {
	ctx := context.Background()

	s := newSystem(t)
	defer s.stop()

	s.addRemote(remote1)
	s.addShare(remote1, share11, tailfs.PermissionReadWrite)

	// Create a file slightly longer than our max rewind buffer of 512
	fileLength := webdavfs.MaxRewindBuffer + 1
	data := make([]byte, fileLength)
	for i := 0; i < fileLength; i++ {
		data[i] = byte(i % 256)
	}
	s.writeFile("writing file to read/write remote should succeed", remote1, share11, file111, string(data), true)

	// Try reading and rewinding in every size up to the maximum buffer length
	for i := 0; i < webdavfs.MaxRewindBuffer; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			f, err := s.fs.OpenFile(ctx, pathTo(remote1, share11, file111), os.O_RDONLY, 0)
			if err != nil {
				t.Fatalf("failed top OpenFile for read: %s", err)
			}
			defer f.Close()

			b := make([]byte, fileLength)

			n, err := io.ReadFull(f, b[:i])
			if err != nil {
				t.Fatalf("failed to read first %d bytes from file: %s", i, err)
			}
			if n != i {
				log.Fatalf("Reading first %d bytes should report correct count, but reported %d", i, n)
			}

			_, err = f.Seek(0, io.SeekStart)
			if err != nil {
				t.Fatalf("failed to seek back %d bytes: %s", i, err)
			}

			n, err = io.ReadFull(f, b)
			if err != nil {
				t.Fatalf("failed to read full file: %s", err)
			}
			if n != fileLength {
				t.Fatalf("reading full file reported incorrect count, got %d, want %d", n, fileLength)
			}
			if string(b) != string(data) {
				t.Fatalf("read wrong data, got %q, want %q", b, data)
			}

			_, err = f.Seek(0, io.SeekStart)
			if err == nil {
				t.Fatal("Attempting to seek to beginning of file after having read past rewind buffer should fail")
			}
		})
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
	fs      webdav.FileSystem
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

	return &system{
		t:     t,
		local: &local{l: l, fs: fs},
		fs: webdavfs.New(webdavfs.Options{
			URL:       fmt.Sprintf("http://%s", l.Addr()),
			Transport: &http.Transport{DisableKeepAlives: true},
		}),
		remotes: make(map[string]*remote),
	}
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
	s.local.fs.SetRemotes(domain, remotes, &http.Transport{})
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
	file, err := s.fs.OpenFile(context.Background(), path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if expectSuccess && err != nil {
		s.t.Fatalf("%v: expected success writing file %q, but got error %v", label, path, err)
	}
	defer func() {
		if !expectSuccess && err == nil {
			s.t.Fatalf("%v: expected error writing file %q", label, path)
		}
	}()

	defer func() {
		err = file.Close()
		if expectSuccess && err != nil {
			s.t.Fatalf("error closing %v: %v", path, err)
		}
	}()

	_, err = file.Write([]byte(contents))
	if expectSuccess && err != nil {
		s.t.Fatalf("%v: writing file %q: %v", label, path, err)
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
	file, err := s.fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
	if err != nil {
		s.t.Fatalf("failed to OpenFile: %s", err)
	}

	got, err := file.Readdir(0)
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

func (s *system) checkDirListIncremental(label string, path string, want ...string) {
	file, err := s.fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
	if err != nil {
		s.t.Fatal(err)
	}

	var gotNames []string
	for {
		got, err := file.Readdir(1)
		for _, fi := range got {
			gotNames = append(gotNames, fi.Name())
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			s.t.Fatalf("failed to Readdir: %s", err)
		}
	}

	if len(want) == 0 && len(gotNames) == 0 {
		return
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
	fi, err := s.fs.Stat(context.Background(), path)
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
	file, err := s.fs.OpenFile(context.Background(), path, os.O_RDONLY, 0)
	if err != nil {
		s.t.Fatalf("failed to OpenFile: %s", err)
	}
	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		s.t.Fatalf("failed to ReadAll: %s", err)
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
