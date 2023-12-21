// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package compositefs provides a webdav.FileSystem that is composi
package compositefs

import (
	"io"
	"log"
	"os"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/util/pathutil"
)

// childrenByName is a slice of *child sorted in name order
type childrenByName []*Child

func (children childrenByName) Len() int           { return len(children) }
func (children childrenByName) Swap(i, j int)      { children[i], children[j] = children[j], children[i] }
func (children childrenByName) Less(i, j int) bool { return children[i].Name < children[j].Name }

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

func (child *Child) defaultAvailable() {
	if child.Available == nil {
		child.Available = func() bool { return true }
	}
}

// CompositeFileSystem is a webdav.FileSystem that is composed of multiple
// child webdav.FileSystems. Each child is identified by a name and appears
// as a folder within the root of the CompositeFileSystem, with the children
// sorted alphabetically by name.
//
// Children in a CompositeFileSystem can only be added or removed via calls to
// the CompositeFileSystem's SDK methods. From a file system perspective, the
// root of the CompositeFileSystem acts as read-only, not permitting the
// addition, removal or renaming of folders.
//
// Rename is only supported within a single child. Renaming across children
// is not supported, as it wouldn't be possible to perform it atomically.
type CompositeFileSystem interface {
	webdav.FileSystem
	io.Closer

	// AddChild ads a single child with the given name, replacing any existing
	// child with the same name.
	AddChild(child *Child)
	// RemoveChild removes the child with the given name, if it exists.
	RemoveChild(name string)
	// SetChildren replaces the entire existing set of children with the given
	// ones.
	SetChildren(children ...*Child)
	// GetChild returns the child with the given name and a boolean indicating
	// whether or not it was found.
	GetChild(name string) (webdav.FileSystem, bool)
}

type Opts struct {
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
func New(opts *Opts) CompositeFileSystem {
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	fs := &compositeFileSystem{
		logf:         logf,
		statChildren: opts.StatChildren,
		childrenMap:  make(map[string]*Child, 0),
	}
	if opts.Clock != nil {
		fs.now = opts.Clock.Now
	} else {
		fs.now = time.Now
	}
	return fs
}

type compositeFileSystem struct {
	logf         logger.Logf
	statChildren bool
	now          func() time.Time
	children     childrenByName
	childrenMap  map[string]*Child
	childrenMu   sync.Mutex
}

func (cfs *compositeFileSystem) AddChild(child *Child) {
	child.defaultAvailable()
	cfs.childrenMu.Lock()
	defer cfs.childrenMu.Unlock()
	cfs.childrenMap[child.Name] = child
	cfs.rebuildChildren()
}

func (cfs *compositeFileSystem) RemoveChild(name string) {
	cfs.childrenMu.Lock()
	oldChild, hadOldChild := cfs.childrenMap[name]
	delete(cfs.childrenMap, name)
	cfs.rebuildChildren()
	cfs.childrenMu.Unlock()
	if hadOldChild {
		closer, ok := oldChild.FS.(io.Closer)
		if ok {
			_ = closer.Close()
		}
	}
}

func (cfs *compositeFileSystem) SetChildren(children ...*Child) {
	newChildrenMap := make(map[string]*Child, len(cfs.children))
	for _, child := range children {
		child.defaultAvailable()
		newChildrenMap[child.Name] = child
	}
	cfs.childrenMu.Lock()
	oldChildren := cfs.children
	cfs.childrenMap = newChildrenMap
	cfs.rebuildChildren()
	cfs.childrenMu.Unlock()
	for _, child := range oldChildren {
		closer, ok := child.FS.(io.Closer)
		if ok {
			_ = closer.Close()
		}
	}
}

func (cfs *compositeFileSystem) GetChild(name string) (webdav.FileSystem, bool) {
	cfs.childrenMu.Lock()
	defer cfs.childrenMu.Unlock()

	child, ok := cfs.childrenMap[name]
	if !ok {
		return nil, false
	}
	return child.FS, true
}

func (cfs *compositeFileSystem) rebuildChildren() {
	cfs.children = make(childrenByName, 0, len(cfs.childrenMap))
	for _, c := range cfs.childrenMap {
		cfs.children = append(cfs.children, c)
	}
	sort.Sort(cfs.children)
}

// pathToChild takes the given name and determines if the path is on a child
// filesystem based on the first path component. If it is, this returns the
// remainder of the path minus the first path component, true, and the
// corresponding child. If it is not, this returns the original name, false,
// and a nil *child.
//
// If the first path component identifies an unknown child, this will return
// os.ErrNotExist.
func (cfs *compositeFileSystem) pathToChild(name string) (string, bool, *Child, error) {
	pathComponents := pathutil.Split(name)
	cfs.childrenMu.Lock()
	child, childFound := cfs.childrenMap[pathComponents[0]]
	cfs.childrenMu.Unlock()
	onChild := len(pathComponents) > 1
	if !childFound {
		return name, onChild, nil, os.ErrNotExist
	}

	return path.Join(pathComponents[1:]...), onChild, child, nil
}

func (cfs *compositeFileSystem) Close() error {
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
