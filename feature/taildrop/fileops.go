// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"errors"
	"io"
	"os"
)

// FileOps abstracts over both local‐FS paths and Android SAF URIs.
type FileOps interface {
	// OpenWriter creates or truncates a file named relative to the receiver's root,
	// seeking to the specified offset. If the file does not exist, it is created with mode perm
	// on platforms that support it.
	//
	// It returns an [io.WriteCloser] and the file's absolute path, or an error.
	OpenWriter(name string, offset int64, perm os.FileMode) (wc io.WriteCloser, path string, err error)
	// Base returns the last element of path.
	Base(path string) string
	// Remove deletes the given entry, where "name" is always a basename.
	Remove(name string) error
	// Rename atomically renames oldPath to a new file named newName,
	// returning the full new path or an error.
	Rename(oldPath, newName string) (newPath string, err error)

	// ListFileNames returns just the basenames of all regular files
	// in the given subdirectory, in a single slice.
	ListFiles(dir string) ([]string, error)
}

var newDefaultFileOps = func(dir string) (FileOps, error) { return nil, errors.New("FileOps is not implemented") }

// DefaultFileOps is the non‑Android FileOps implementation.
// It exists on Android too so the stub constructor can compile,
// but Android never uses the value.
type DefaultFileOps struct{ rootDir string }
