// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive_magic

package driveimpl

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"tailscale.com/drive"
)

// addMagicShare configures the named remote to expose a magic share.
// The share's on-disk path is returned so the caller can prepopulate
// ACL directories.
func (s *system) addMagicShare(remoteName, shareName, peerLogin, sharerLogin string) string {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}

	folder := s.t.TempDir()
	r.shares[shareName] = folder
	r.permissions[shareName] = drive.PermissionReadWrite
	r.peerLogin = peerLogin
	r.sharerLogin = sharerLogin

	shares := make([]*drive.Share, 0, len(r.shares))
	for n, f := range r.shares {
		shares = append(shares, &drive.Share{Name: n, Path: f})
	}
	slices.SortFunc(shares, drive.CompareShares)
	r.fs.SetShares(shares)
	r.fileServer.SetShares(r.shares)
	return folder
}

// setPeer rebinds the peer/sharer login for the given remote. The remote's
// ServeHTTP picks up these values on each request, so this works for tests
// that simulate different peer identities against the same sharer.
func (s *system) setPeer(remoteName, peerLogin, sharerLogin string) {
	r, ok := s.remotes[remoteName]
	if !ok {
		s.t.Fatalf("unknown remote %q", remoteName)
	}
	r.mu.Lock()
	r.peerLogin = peerLogin
	r.sharerLogin = sharerLogin
	r.mu.Unlock()
}

func mkdir(t *testing.T, parent, name string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(parent, name), 0755); err != nil {
		t.Fatalf("mkdir %q: %v", name, err)
	}
}

func TestMagicShareDiscoveryAndListing(t *testing.T) {
	const (
		magicShare    = "magic"
		sharerLogin   = "fserb@example.com"
		peerRhea      = "rhea@example.com"
		peerJoe       = "joe@example.com"
		peerStranger  = "stranger@example.com"
		dirSharerOnly = "fserb"
		dirSharerRhea = "fserb+rhea"
		dirNoSharer   = "rhea+joe"   // invalid: no sharer
		dirGarbage    = "not a name" // invalid grammar
	)

	s := newSystem(t)
	s.addRemote(remote1)
	folder := s.addMagicShare(remote1, magicShare, peerRhea, sharerLogin)

	mkdir(t, folder, dirSharerOnly)
	mkdir(t, folder, dirSharerRhea)
	mkdir(t, folder, dirNoSharer)
	mkdir(t, folder, dirGarbage)

	// rhea sees only the dirs that name both sharer and rhea.
	checkMagicListing(t, s, magicShare, []string{dirSharerRhea})

	// joe is matched by no dir.
	s.setPeer(remote1, peerJoe, sharerLogin)
	checkMagicListing(t, s, magicShare, nil)

	// fserb on another node sees their own dirs.
	s.setPeer(remote1, sharerLogin, sharerLogin)
	checkMagicListing(t, s, magicShare, []string{dirSharerOnly, dirSharerRhea})

	// A peer not in any dir, but with the share grant, gets an empty
	// listing (not 404).
	s.setPeer(remote1, peerStranger, sharerLogin)
	checkMagicListing(t, s, magicShare, nil)
}

func TestMagicShareReadWrite(t *testing.T) {
	const (
		magicShare  = "magic"
		sharerLogin = "fserb@example.com"
		peerRhea    = "rhea@example.com"
		peerJoe     = "joe@example.com"
		dirShared   = "fserb+rhea"
		dirOther    = "fserb"
		dirInvalid  = "rhea+joe"
		fname       = "note.txt"
	)

	s := newSystem(t)
	s.addRemote(remote1)
	folder := s.addMagicShare(remote1, magicShare, peerRhea, sharerLogin)

	mkdir(t, folder, dirShared)
	mkdir(t, folder, dirOther)
	mkdir(t, folder, dirInvalid)

	// rhea can read/write inside dirShared.
	rheaPath := path.Join(domain, remote1, magicShare, dirShared, fname)
	if err := s.client.Write(rheaPath, []byte("hi from rhea"), 0644); err != nil {
		t.Fatalf("rhea write into %q: %v", dirShared, err)
	}
	// Verify it actually landed on disk under the share folder.
	onDisk := filepath.Join(folder, dirShared, fname)
	if b, err := os.ReadFile(onDisk); err != nil {
		t.Fatalf("on-disk read after write: %v (file %s)", err, onDisk)
	} else if string(b) != "hi from rhea" {
		t.Fatalf("on-disk content %q != written %q", b, "hi from rhea")
	}
	got, err := s.client.Read(rheaPath)
	if err != nil {
		t.Fatalf("rhea read from %q: %v", dirShared, err)
	}
	if string(got) != "hi from rhea" {
		t.Errorf("rhea read got %q, want %q", got, "hi from rhea")
	}

	// rhea cannot write into a dir she's not in.
	otherPath := path.Join(domain, remote1, magicShare, dirOther, fname)
	if err := s.client.Write(otherPath, []byte("nope"), 0644); err == nil {
		t.Errorf("rhea write into %q should have failed", dirOther)
	}

	// rhea cannot read from a dir she's not in.
	if _, err := s.client.Read(otherPath); err == nil {
		t.Errorf("rhea read from %q should have failed", dirOther)
	}

	// dirInvalid is invalid (no sharer in name): nobody, including the
	// principals named, can access it.
	s.setPeer(remote1, peerJoe, sharerLogin)
	invalidPath := path.Join(domain, remote1, magicShare, dirInvalid, fname)
	if err := s.client.Write(invalidPath, []byte("x"), 0644); err == nil {
		t.Errorf("joe write into invalid dir %q should have failed", dirInvalid)
	}

	// joe also cannot list anything (no matching dirs).
	checkMagicListing(t, s, magicShare, nil)
}

func TestMagicShareTopLevelMutationsDenied(t *testing.T) {
	const (
		magicShare  = "magic"
		sharerLogin = "fserb@example.com"
		peerRhea    = "rhea@example.com"
		dirShared   = "fserb+rhea"
	)

	s := newSystem(t)
	s.addRemote(remote1)
	folder := s.addMagicShare(remote1, magicShare, peerRhea, sharerLogin)
	mkdir(t, folder, dirShared)

	// MKCOL of a brand new top-level dir name must fail.
	newDir := path.Join(domain, remote1, magicShare, "fserb+rhea+joe")
	if err := s.client.Mkdir(newDir, 0755); err == nil {
		t.Errorf("mkcol of new top-level dir should have been denied")
	}

	// DELETE of an existing top-level dir must fail.
	existingDir := path.Join(domain, remote1, magicShare, dirShared)
	if err := s.client.RemoveAll(existingDir); err == nil {
		t.Errorf("delete of existing top-level dir should have been denied")
	}

	// But files inside the dir can be deleted normally.
	filePath := path.Join(existingDir, "f.txt")
	if err := s.client.Write(filePath, []byte("hi"), 0644); err != nil {
		t.Fatalf("write inside acl dir: %v", err)
	}
	if err := s.client.Remove(filePath); err != nil {
		t.Errorf("delete inside acl dir failed: %v", err)
	}
}

// checkMagicListing verifies that a depth-1 listing of /<domain>/<remote>/<magicShare>/
// returns exactly want (in any order).
func checkMagicListing(t *testing.T, s *system, magicShare string, want []string) {
	t.Helper()
	entries, err := s.client.ReadDir(path.Join(domain, remote1, magicShare))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	if !slices.Equal(got, sortedWant) {
		t.Errorf("listing got %v, want %v", got, sortedWant)
	}
}
