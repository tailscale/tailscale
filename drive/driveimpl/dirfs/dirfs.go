// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dirfs provides a webdav.FileSystem that looks like a read-only
// directory containing only subdirectories.
package dirfs

import (
	"slices"
	"strings"
	"time"

	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/tstime"
)

// Child is subdirectory of an FS.
type Child struct {
	// Name is the name of the child
	Name string

	// Available is a function indicating whether or not the child is currently
	// available. Unavailable children are excluded from the FS's directory
	// listing. Available must be safe for concurrent use.
	Available func() bool
}

func (c *Child) isAvailable() bool {
	if c.Available == nil {
		return true
	}
	return c.Available()
}

// FS is a read-only webdav.FileSystem that is composed of multiple child
// folders.
//
// When listing the contents of this FileSystem's root directory, children will
// be ordered in the order they're given to the FS.
//
// Children in an FS cannot be added, removed or renamed via operations on the
// webdav.FileSystem interface like filesystem.Mkdir or filesystem.OpenFile.
//
// Any attempts to perform operations on paths inside of children will result
// in a panic, as these are not expected to be performed on this FS.
//
// An FS an optionally have a StaticRoot, which will insert a folder with that
// StaticRoot into the tree, like this:
//
// -- <StaticRoot>
// ----- <Child>
// ----- <Child>
type FS struct {
	// Children configures the full set of children of this FS.
	Children []*Child

	// Clock, if given, will cause this FS to use Clock.now() as the current
	// time.
	Clock tstime.Clock

	// StaticRoot, if given, will insert the given name as a static root into
	// every path.
	StaticRoot string
}

func (dfs *FS) findChild(name string) (int, *Child) {
	var child *Child
	i, found := slices.BinarySearchFunc(dfs.Children, name, func(child *Child, name string) int {
		return strings.Compare(child.Name, name)
	})
	if found {
		child = dfs.Children[i]
	}
	return i, child
}

// childFor returns the child for the given filename. If the filename refers to
// a path inside of a child, this will panic.
func (dfs *FS) childFor(name string) *Child {
	pathComponents := shared.CleanAndSplit(name)
	if len(pathComponents) != 1 {
		panic("dirfs does not permit reaching into child directories")
	}
	_, child := dfs.findChild(pathComponents[0])
	return child
}

func (dfs *FS) now() time.Time {
	if dfs.Clock != nil {
		return dfs.Clock.Now()
	}
	return time.Now()
}

func (dfs *FS) trimStaticRoot(name string) (string, bool) {
	before, after, found := strings.Cut(name, "/"+dfs.StaticRoot)
	if !found {
		return before, false
	}
	return after, shared.IsRoot(after)
}
