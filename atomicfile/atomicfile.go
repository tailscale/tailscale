// Copyright (c) 2019 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package atomicfile contains code related to writing to filesystems
// atomically.
//
// This package should be considered internal; its API is not stable.
package atomicfile // import "tailscale.com/atomicfile"

import (
	"fmt"
	"os"
)

// WriteFile writes data to filename+some suffix, then renames it
// into filename.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	tmpname := filename + ".new.tmp"

	f, err := os.OpenFile(tmpname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err == nil {
		return err
	}

	if err := os.Rename(tmpname, filename); err != nil {
		return fmt.Errorf("%#v->%#v: %v", tmpname, filename, err)
	}
	return nil
}
