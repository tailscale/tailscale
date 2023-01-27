// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dirwalk contains code to walk a directory.
package dirwalk

import (
	"io"
	"io/fs"
	"os"

	"go4.org/mem"
)

var osWalkShallow func(name mem.RO, fn WalkFunc) error

// WalkFunc is the callback type used with WalkShallow.
//
// The name and de are only valid for the duration of func's call
// and should not be retained.
type WalkFunc func(name mem.RO, de fs.DirEntry) error

// WalkShallow reads the entries in the named directory and calls fn for each.
// It does not recurse into subdirectories.
//
// If fn returns an error, iteration stops and WalkShallow returns that value.
//
// On Linux, WalkShallow does not allocate, so long as certain methods on the
// WalkFunc's DirEntry are not called which necessarily allocate.
func WalkShallow(dirName mem.RO, fn WalkFunc) error {
	if f := osWalkShallow; f != nil {
		return f(dirName, fn)
	}
	of, err := os.Open(dirName.StringCopy())
	if err != nil {
		return err
	}
	defer of.Close()
	for {
		fis, err := of.ReadDir(100)
		for _, de := range fis {
			if err := fn(mem.S(de.Name()), de); err != nil {
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
