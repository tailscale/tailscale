// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"io"
	"io/fs"
	"os"
)

// FileOps abstracts over both local‐FS paths and Android SAF URIs.
type FileOps interface {
	// OpenWriter creates or truncates a file named relative to the receiver's root,
	// seeking to the specified offset. If the file does not exist, it is created with mode perm
	// on platforms that support it.
	//
	// It returns an [io.WriteCloser] and the file's absolute path, or an error.
	// This call may block. Callers should avoid holding locks when calling OpenWriter.
	OpenWriter(name string, offset int64, perm os.FileMode) (wc io.WriteCloser, path string, err error)

	// Remove deletes a file or directory relative to the receiver's root.
	// It returns [io.ErrNotExist] if the file or directory does not exist.
	Remove(name string) error

	// Rename atomically renames oldPath to a new file named newName,
	// returning the full new path or an error.
	Rename(oldPath, newName string) (newPath string, err error)

	// ListFiles returns just the basenames of all regular files
	// in the root directory.
	ListFiles() ([]string, error)

	// Stat returns the FileInfo for the given name or an error.
	Stat(name string) (fs.FileInfo, error)

	// OpenReader opens the given basename for the given name or an error.
	OpenReader(name string) (io.ReadCloser, error)
}

var newFileOps func(dir string) (FileOps, error)
