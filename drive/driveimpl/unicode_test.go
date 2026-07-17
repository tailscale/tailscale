// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/drive"
)

// Unicode filenames from https://github.com/tailscale/tailscale/issues/15020,
// in both NFC (precomposed) and NFD (decomposed) forms. The two forms are
// canonically equivalent but byte-wise different, so on
// normalization-sensitive filesystems like ext4 they name different files.
const (
	nfcName = "\u30c6\u30ba\u30c8 \u00e4.wav"        // テズト ä.wav, precomposed
	nfdName = "\u30c6\u30b9\u3099\u30c8 a\u0308.wav" // same name, decomposed
	nfcDir  = "\u30ae\u30bf\u30fc"                   // ギター, precomposed
	nfdDir  = "\u30ad\u3099\u30bf\u30fc"             // same name, decomposed
)

// TestUnicodeRoundTrip verifies that a file written via WebDAV with a
// non-ASCII name can be statted and read back with the identical name.
func TestUnicodeRoundTrip(t *testing.T) {
	s := newSystem(t)
	s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)

	s.writeFile("writing unicode file should succeed", remote1, share11, nfcName, "hello", true)
	s.checkFileStatus(remote1, share11, nfcName)
	s.checkFileContents(remote1, share11, nfcName)
}

// TestUnicodeNormalizationMismatch verifies that a file whose on-disk name is
// in one Unicode normalization form can be read, statted and overwritten via
// WebDAV using a canonically equivalent name in the other form. This is what
// happens when a macOS WebDAV client (which sends NFD paths) accesses a share
// with NFC filenames on disk, and vice versa.
func TestUnicodeNormalizationMismatch(t *testing.T) {
	tests := []struct {
		name               string
		onDisk, viaRequest string
	}{
		{"nfc-on-disk-nfd-request", nfcName, nfdName},
		{"nfd-on-disk-nfc-request", nfdName, nfcName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSystem(t)
			s.addRemote(remote1)
			s.addShare(remote1, share11, drive.PermissionReadWrite)

			// Write the file directly to disk with one form, then read and
			// stat it via WebDAV using the other form.
			s.write(remote1, share11, tt.onDisk, "hello world")
			if got := s.readViaWebDAV(remote1, share11, tt.viaRequest); got != "hello world" {
				t.Errorf("read: got %q, want %q", got, "hello world")
			}
			s.statViaWebDAV(remote1, share11, tt.viaRequest)

			// Overwriting via the other form must update the existing file
			// rather than creating a second one.
			s.writeFile("overwrite with equivalent name should succeed", remote1, share11, tt.viaRequest, "updated", true)
			if got := s.read(remote1, share11, tt.onDisk); got != "updated" {
				t.Errorf("read from disk after overwrite: got %q, want %q", got, "updated")
			}
			shareDir := s.remotes[remote1].shares[share11]
			entries, err := os.ReadDir(shareDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Errorf("got %d files on disk, want 1: %q", len(entries), entries)
			}
		})
	}
}

// TestUnicodeNormalizationMismatchInDir is like
// TestUnicodeNormalizationMismatch, but with the mismatch in a directory
// component of the path rather than in the filename.
func TestUnicodeNormalizationMismatchInDir(t *testing.T) {
	s := newSystem(t)
	s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)

	shareDir := s.remotes[remote1].shares[share11]
	if err := os.Mkdir(filepath.Join(shareDir, nfcDir), 0755); err != nil {
		t.Fatal(err)
	}
	s.write(remote1, share11, filepath.Join(nfcDir, nfcName), "hello world")

	got := s.readViaWebDAV(remote1, share11, nfdDir+"/"+nfdName)
	if got != "hello world" {
		t.Errorf("read: got %q, want %q", got, "hello world")
	}
}

// TestUnicodeNewFileKeepsRequestedName verifies that creating a new file
// keeps the exact bytes of the name that the client sent when no equivalent
// file exists yet.
func TestUnicodeNewFileKeepsRequestedName(t *testing.T) {
	s := newSystem(t)
	s.addRemote(remote1)
	s.addShare(remote1, share11, drive.PermissionReadWrite)

	s.writeFile("writing new NFD file should succeed", remote1, share11, nfdName, "hello", true)
	if got := s.read(remote1, share11, nfdName); got != "hello" {
		t.Errorf("read from disk: got %q, want %q", got, "hello")
	}
}
