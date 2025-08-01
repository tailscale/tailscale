// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//go:build !android

package taildrop

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

var renameMu sync.Mutex

// fsFileOps implements FileOps using the local filesystem rooted at a directory.
// It is used on non-Android platforms.
type fsFileOps struct{ rootDir string }

func init() {
	newFileOps = func(dir string) (FileOps, error) {
		if dir == "" {
			return nil, errors.New("rootDir cannot be empty")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %q: %w", dir, err)
		}
		return fsFileOps{rootDir: dir}, nil
	}
}

func (f fsFileOps) OpenWriter(name string, offset int64, perm os.FileMode) (io.WriteCloser, string, error) {
	path, err := joinDir(f.rootDir, name)
	if err != nil {
		return nil, "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	fi, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return nil, "", err
	}
	if offset != 0 {
		curr, err := fi.Seek(0, io.SeekEnd)
		if err != nil {
			fi.Close()
			return nil, "", err
		}
		if offset < 0 || offset > curr {
			fi.Close()
			return nil, "", fmt.Errorf("offset %d out of range", offset)
		}
		if _, err := fi.Seek(offset, io.SeekStart); err != nil {
			fi.Close()
			return nil, "", err
		}
		if err := fi.Truncate(offset); err != nil {
			fi.Close()
			return nil, "", err
		}
	}
	return fi, path, nil
}

func (f fsFileOps) Remove(name string) error {
	path, err := joinDir(f.rootDir, name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// Rename moves the partial file into its final name.
// newName must be a base name (not absolute or containing path separators).
// It will retry up to 10 times, de-dup same-checksum files, etc.
func (f fsFileOps) Rename(oldPath, newName string) (newPath string, err error) {
	var dst string
	if filepath.IsAbs(newName) || strings.ContainsRune(newName, os.PathSeparator) {
		return "", fmt.Errorf("invalid newName %q: must not be an absolute path or contain path separators", newName)
	}

	dst = filepath.Join(f.rootDir, newName)

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}

	st, err := os.Stat(oldPath)
	if err != nil {
		return "", err
	}
	wantSize := st.Size()

	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		renameMu.Lock()
		fi, statErr := os.Stat(dst)
		// Atomically rename the partial file as the destination file if it doesn't exist.
		// Otherwise, it returns the length of the current destination file.
		// The operation is atomic.
		if os.IsNotExist(statErr) {
			err = os.Rename(oldPath, dst)
			renameMu.Unlock()
			if err != nil {
				return "", err
			}
			return dst, nil
		}
		if statErr != nil {
			renameMu.Unlock()
			return "", statErr
		}
		gotSize := fi.Size()
		renameMu.Unlock()

		// Avoid the final rename if a destination file has the same contents.
		//
		// Note: this is best effort and copying files from iOS from the Media Library
		// results in processing on the iOS side which means the size and shas of the
		// same file can be different.
		if gotSize == wantSize {
			sumP, err := sha256File(oldPath)
			if err != nil {
				return "", err
			}
			sumD, err := sha256File(dst)
			if err != nil {
				return "", err
			}
			if bytes.Equal(sumP[:], sumD[:]) {
				if err := os.Remove(oldPath); err != nil {
					return "", err
				}
				return dst, nil
			}
		}

		// Choose a new destination filename and try again.
		dst = filepath.Join(filepath.Dir(dst), nextFilename(filepath.Base(dst)))
	}

	return "", fmt.Errorf("too many retries trying to rename %q to %q", oldPath, newName)
}

// sha256File computes the SHA‑256 of a file.
func sha256File(path string) (sum [sha256.Size]byte, _ error) {
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func (f fsFileOps) ListFiles() ([]string, error) {
	entries, err := os.ReadDir(f.rootDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func (f fsFileOps) Stat(name string) (fs.FileInfo, error) {
	path, err := joinDir(f.rootDir, name)
	if err != nil {
		return nil, err
	}
	return os.Stat(path)
}

func (f fsFileOps) OpenReader(name string) (io.ReadCloser, error) {
	path, err := joinDir(f.rootDir, name)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// joinDir is like [filepath.Join] but returns an error if baseName is too long,
// is a relative path instead of a basename, or is otherwise invalid or unsafe for incoming files.
func joinDir(dir, baseName string) (string, error) {
	if !utf8.ValidString(baseName) ||
		strings.TrimSpace(baseName) != baseName ||
		len(baseName) > 255 {
		return "", ErrInvalidFileName
	}
	// TODO: validate unicode normalization form too? Varies by platform.
	clean := path.Clean(baseName)
	if clean != baseName || clean == "." || clean == ".." {
		return "", ErrInvalidFileName
	}
	for _, r := range baseName {
		if !validFilenameRune(r) {
			return "", ErrInvalidFileName
		}
	}
	if !filepath.IsLocal(baseName) {
		return "", ErrInvalidFileName
	}
	return filepath.Join(dir, baseName), nil
}
