// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package compositefs provides a webdav.FileSystem that is composi
package compositefs

import (
	"io"
	"log"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/tailfs/shared"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// Child is a child filesystem of a CompositeFileSystem
type Child struct {
	// Name is the name of the child
	Name string
	// FS is the child's FileSystem
	FS webdav.FileSystem
	// Available is a function indicating whether or not the child is currently
	// available.
	Available func() bool
}

func (c *Child) isAvailable() bool {
	if c.Available == nil {
		return true
	}
	return c.Available()
}

// Options specifies options for configuring a CompositeFileSystem.
type Options struct {
	// Logf specifies a logging function to use
	Logf logger.Logf
	// StatChildren, if true, causes the CompositeFileSystem to stat its child
	// folders when generating a root directory listing. This gives more
	// accurate information but increases latency.
	StatChildren bool
	// Clock, if specified, determines the current time. If not specified, we
	// default to time.Now().
	Clock tstime.Clock
}

// New constructs a CompositeFileSystem that logs using the given logf.
func New(opts Options) *CompositeFileSystem {
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	fs := &CompositeFileSystem{
		logf:         logf,
		statChildren: opts.StatChildren,
	}
	if opts.Clock != nil {
		fs.now = opts.Clock.Now
	} else {
		fs.now = time.Now
	}
	return fs
}

// CompositeFileSystem is a webdav.FileSystem that is composed of multiple
// child webdav.FileSystems. Each child is identified by a name and appears
// as a folder within the root of the CompositeFileSystem, with the children
// sorted lexicographically by name.
//
// Children in a CompositeFileSystem can only be added or removed via calls to
// the AddChild and RemoveChild methods, they cannot be added via operations
// on the webdav.FileSystem interface like filesystem.Mkdir or filesystem.OpenFile.
// In other words, the root of the CompositeFileSystem acts as read-only, not
// permitting the addition, removal or renaming of folders.
//
// Rename is only supported within a single child. Renaming across children
// is not supported, as it wouldn't be possible to perform it atomically.
type CompositeFileSystem struct {
	logf         logger.Logf
	statChildren bool
	now          func() time.Time

	// childrenMu guards children
	childrenMu sync.Mutex
	children   []*Child
}

// AddChild ads a single child with the given name, replacing any existing
// child with the same name.
func (cfs *CompositeFileSystem) AddChild(child *Child) {
	cfs.childrenMu.Lock()
	oldIdx, oldChild := cfs.findChildLocked(child.Name)
	if oldChild != nil {
		// replace old child
		cfs.children[oldIdx] = child
	} else {
		// insert new child
		cfs.children = slices.Insert(cfs.children, oldIdx, child)
	}
	cfs.childrenMu.Unlock()

	if oldChild != nil {
		if c, ok := oldChild.FS.(io.Closer); ok {
			if err := c.Close(); err != nil {
				cfs.logf("closing child filesystem %v: %v", child.Name, err)
			}
		}
	}
}

// RemoveChild removes the child with the given name, if it exists.
func (cfs *CompositeFileSystem) RemoveChild(name string) {
	cfs.childrenMu.Lock()
	oldPos, oldChild := cfs.findChildLocked(name)
	if oldChild != nil {
		// remove old child
		copy(cfs.children[oldPos:], cfs.children[oldPos+1:])
		cfs.children = cfs.children[:len(cfs.children)-1]
	}
	cfs.childrenMu.Unlock()

	if oldChild != nil {
		closer, ok := oldChild.FS.(io.Closer)
		if ok {
			err := closer.Close()
			if err != nil {
				cfs.logf("failed to close child filesystem %v: %v", name, err)
			}
		}
	}
}

// SetChildren replaces the entire existing set of children with the given
// ones.
func (cfs *CompositeFileSystem) SetChildren(children ...*Child) {
	slices.SortFunc(children, func(a, b *Child) int {
		return strings.Compare(a.Name, b.Name)
	})

	cfs.childrenMu.Lock()
	oldChildren := cfs.children
	cfs.children = children
	cfs.childrenMu.Unlock()

	for _, child := range oldChildren {
		closer, ok := child.FS.(io.Closer)
		if ok {
			_ = closer.Close()
		}
	}
}

// GetChild returns the child with the given name and a boolean indicating
// whether or not it was found.
func (cfs *CompositeFileSystem) GetChild(name string) (webdav.FileSystem, bool) {
	_, child := cfs.findChildLocked(name)
	if child == nil {
		return nil, false
	}
	return child.FS, true
}

func (cfs *CompositeFileSystem) findChildLocked(name string) (int, *Child) {
	var child *Child
	i, found := slices.BinarySearchFunc(cfs.children, name, func(child *Child, name string) int {
		return strings.Compare(child.Name, name)
	})
	if found {
		child = cfs.children[i]
	}
	return i, child
}

// pathInfoFor returns a pathInfo for the given filename. If the filename
// refers to a Child that does not exist within this CompositeFileSystem,
// it will return the error os.ErrNotExist. Even when returning an error,
// it will still return a complete pathInfo.
func (cfs *CompositeFileSystem) pathInfoFor(name string) (pathInfo, error) {
	cfs.childrenMu.Lock()
	defer cfs.childrenMu.Unlock()

	var info pathInfo
	pathComponents := shared.CleanAndSplit(name)
	_, info.child = cfs.findChildLocked(pathComponents[0])
	info.refersToChild = len(pathComponents) == 1
	if !info.refersToChild {
		info.pathOnChild = path.Join(pathComponents[1:]...)
	}
	if info.child == nil {
		return info, os.ErrNotExist
	}
	return info, nil
}

// pathInfo provides information about a path
type pathInfo struct {
	// child is the Child corresponding to the first component of the path.
	child *Child
	// refersToChild indicates that that path refers directly to the child
	// (i.e. the path has only 1 component).
	refersToChild bool
	// pathOnChild is the path within the child (i.e. path minus leading component)
	// if and only if refersToChild is false.
	pathOnChild string
}

func (cfs *CompositeFileSystem) Close() error {
	cfs.childrenMu.Lock()
	children := cfs.children
	cfs.childrenMu.Unlock()

	for _, child := range children {
		closer, ok := child.FS.(io.Closer)
		if ok {
			_ = closer.Close()
		}
	}

	return nil
}
