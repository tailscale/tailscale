// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// The functions in this file are based on go's own cache in
// cmd/go/internal/cache/cache.go, particularly putIndexEntry and copyFile.

// writeActionFile writes the indexEntry metadata for an ActionID to disk. It
// may be called for the same actionID concurrently from multiple processes,
// and the outputID for a specific actionID may change from time to time due
// to non-deterministic builds. It makes a best-effort to delete the file if
// anything goes wrong.
func writeActionFile(dest string, b []byte) (retErr error) {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, 0o666)
	if err != nil {
		return err
	}
	defer func() {
		cerr := f.Close()
		if retErr != nil || cerr != nil {
			retErr = errors.Join(retErr, cerr, os.Remove(dest))
		}
	}()

	_, err = f.Write(b)
	if err != nil {
		return err
	}

	// Truncate the file only *after* writing it.
	// (This should be a no-op, but truncate just in case of previous corruption.)
	//
	// This differs from os.WriteFile, which truncates to 0 *before* writing
	// via os.O_TRUNC. Truncating only after writing ensures that a second write
	// of the same content to the same file is idempotent, and does not - even
	// temporarily! - undo the effect of the first write.
	return f.Truncate(int64(len(b)))
}

// writeOutputFile writes content to be cached to disk. The outputID is the
// sha256 hash of the content, and each file should only be written ~once,
// assuming no sha256 hash collisions. It may be written multiple times if
// concurrent processes are both populating the same output. The file is opened
// with FILE_SHARE_READ|FILE_SHARE_WRITE, which means both processes can write
// the same contents concurrently without conflict.
//
// It makes a best effort to clean up if anything goes wrong, but the file may
// be left in an inconsistent state in the event of disk-related errors such as
// another process taking file locks, or power loss etc.
func writeOutputFile(dest string, r io.Reader, size int64, outputID string) (_ int64, retErr error) {
	info, err := os.Stat(dest)
	if err == nil && info.Size() == size {
		// Already exists, check the hash.
		if f, err := os.Open(dest); err == nil {
			h := sha256.New()
			io.Copy(h, f)
			f.Close()
			if fmt.Sprintf("%x", h.Sum(nil)) == outputID {
				// Still drain the reader to ensure associated resources are released.
				return io.Copy(io.Discard, r)
			}
		}
	}

	// Didn't successfully find the pre-existing file, write it.
	mode := os.O_WRONLY | os.O_CREATE
	if err == nil && info.Size() > size {
		mode |= os.O_TRUNC // Should never happen, but self-heal.
	}
	f, err := os.OpenFile(dest, mode, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to open output file %q: %w", dest, err)
	}
	defer func() {
		cerr := f.Close()
		if retErr != nil || cerr != nil {
			retErr = errors.Join(retErr, cerr, os.Remove(dest))
		}
	}()

	// Copy file to f, but also into h to double-check hash.
	h := sha256.New()
	w := io.MultiWriter(f, h)
	n, err := io.Copy(w, r)
	if err != nil {
		return 0, err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != outputID {
		return 0, errors.New("file content changed underfoot")
	}

	return n, nil
}
