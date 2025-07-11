// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package taildrop

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var renameMu sync.Mutex
var defaultFileOps FileOps = DefaultFileOps{}

// DefaultFileOps is the non-Android implementation of FileOps.
type DefaultFileOps struct{}

func (DefaultFileOps) OpenWriter(partialStr string, dest string, offset int64, perm os.FileMode) (io.WriteCloser, string, error) {
	partial := dest + partialStr
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return nil, "", err
	}
	if offset != 0 {
		curr, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			f.Close()
			return nil, "", err
		}
		if offset < 0 || offset > curr {
			f.Close()
			return nil, "", fmt.Errorf("offset %d out of range", offset)
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return nil, "", err
		}
		if err := f.Truncate(offset); err != nil {
			f.Close()
			return nil, "", err
		}
	}
	return f, partial, nil
}

func (DefaultFileOps) Base(pathOrURI string) string {
	return filepath.Base(pathOrURI)
}

func (DefaultFileOps) Remove(name string) error {
	return os.Remove(name)
}

func (DefaultFileOps) Join(dir, name string) string {
	return filepath.Join(dir, name)
}

// Rename moves the partial file into its final name.
// If finalName contains any path separators (or is absolute),
// we use it verbatim; otherwise we join it to the partial’s dir.
// It will retry up to 10 times, de-dup same-checksum files, etc.
func (DefaultFileOps) Rename(partial, finalName string) (string, error) {
	var dstPath string
	if filepath.IsAbs(finalName) || strings.ContainsRune(finalName, os.PathSeparator) {
		dstPath = finalName
	} else {
		dstPath = filepath.Join(filepath.Dir(partial), finalName)
	}

	// grab the size of the partial file once
	stat, err := os.Stat(partial)
	if err != nil {
		return "", err
	}
	fileLength := stat.Size()

	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		renameMu.Lock()
		fi, statErr := os.Stat(dstPath)
		// Atomically rename the partial file as the destination file if it doesn't exist.
		// Otherwise, it returns the length of the current destination file.
		// The operation is atomic.
		if os.IsNotExist(statErr) {
			err = os.Rename(partial, dstPath)
			renameMu.Unlock()
			if err != nil {
				return "", err
			}
			return dstPath, nil
		}
		if statErr != nil {
			renameMu.Unlock()
			return "", statErr
		}
		lengthOnDisk := fi.Size()
		renameMu.Unlock()

		// Avoid the final rename if a destination file has the same contents.
		//
		// Note: this is best effort and copying files from iOS from the Media Library
		// results in processing on the iOS side which means the size and shas of the
		// same file can be different.
		if lengthOnDisk == fileLength {
			partSum, err := sha256File(partial)
			if err != nil {
				return "", err
			}
			dstSum, err := sha256File(dstPath)
			if err != nil {
				return "", err
			}
			if bytes.Equal(partSum[:], dstSum[:]) {
				if err := os.Remove(partial); err != nil {
					return "", err
				}
				return dstPath, nil
			}
		}

		// Choose a new destination filename and try again.
		dstPath = filepath.Join(filepath.Dir(dstPath), nextFilename(filepath.Base(dstPath)))
	}

	return "", fmt.Errorf("too many retries trying to rename partial %q", finalName)
}

// sha256File is borrowed from your old finalizeDirect helper
func sha256File(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
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

func (DefaultFileOps) IsDirect() bool { return true }
