// Copyright 2019 Tailscale & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package atomicfile contains code related to writing to filesystems
// atomically.
//
// This package should be considered internal; its API is not stable.
package atomicfile // import "tailscale.com/atomicfile"

import (
	"fmt"
	"io/ioutil"
	"os"
)

// WriteFile writes data to filename+some suffix, then renames it
// into filename.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	tmpname := filename + ".new.tmp"
	if err := ioutil.WriteFile(tmpname, data, perm); err != nil {
		return fmt.Errorf("%#v: %v", tmpname, err)
	}
	if err := os.Rename(tmpname, filename); err != nil {
		return fmt.Errorf("%#v->%#v: %v", tmpname, filename, err)
	}
	return nil
}
