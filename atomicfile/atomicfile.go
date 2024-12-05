// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package atomicfile contains code related to writing to filesystems
// atomically.
//
// This package should be considered internal; its API is not stable.
package atomicfile // import "tailscale.com/atomicfile"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteFile writes data to filename+some suffix, then renames it into filename.
// The perm argument is ignored on Windows. If the target filename already
// exists but is not a regular file, WriteFile returns an error.
func WriteFile(filename string, data []byte, perm os.FileMode) (err error) {
	fi, err := os.Stat(filename)
	if err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s already exists and is not a regular file", filename)
	}
	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := f.Chmod(perm); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filename)
}
