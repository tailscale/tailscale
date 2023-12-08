// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package compositefs provides a webdav.FileSystem that is composi
package compositefs

import (
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/webdav"
	"tailscale.com/types/logger"
)

// child represents a child filesystem
type child struct {
	name string
	fs   webdav.FileSystem
}

// childrenByName is a slice of *child sorted in name order
type childrenByName []*child

func (children childrenByName) Len() int           { return len(children) }
func (children childrenByName) Swap(i, j int)      { children[i], children[j] = children[j], children[i] }
func (children childrenByName) Less(i, j int) bool { return children[i].name < children[j].name }

type CompositeFileSystem interface {
	webdav.FileSystem
	AddChild(name string, fs webdav.FileSystem)
	RemoveChild(name string)
	SetChildren(map[string]webdav.FileSystem)
	GetChild(name string) (webdav.FileSystem, bool)
}

func New(logf logger.Logf, children ...*child) CompositeFileSystem {
	fs := &compositeFileSystem{
		logf:        logf,
		children:    childrenByName(children),
		childrenMap: make(map[string]*child, len(children)),
	}
	sort.Sort(fs.children)
	for _, c := range children {
		fs.childrenMap[c.name] = c
	}
	return fs
}

type compositeFileSystem struct {
	logf          logger.Logf
	children      childrenByName
	childrenMap   map[string]*child
	childrenMutex sync.Mutex
}

func (cfs *compositeFileSystem) AddChild(name string, childFS webdav.FileSystem) {
	c := &child{
		name: name,
		fs:   childFS,
	}

	cfs.childrenMutex.Lock()
	defer cfs.childrenMutex.Unlock()
	cfs.childrenMap[name] = c
	cfs.rebuildChildren()
}

func (cfs *compositeFileSystem) RemoveChild(name string) {
	cfs.childrenMutex.Lock()
	defer cfs.childrenMutex.Unlock()
	delete(cfs.childrenMap, name)
	cfs.rebuildChildren()
}

func (cfs *compositeFileSystem) SetChildren(children map[string]webdav.FileSystem) {
	// TODO(oxtoacart): we should close the existing webdav filesystems to
	// free up resources, for example the stat cache goroutine.
	newChildrenMap := make(map[string]*child, len(cfs.children))
	for name, childFS := range children {
		newChildrenMap[name] = &child{
			name: name,
			fs:   childFS,
		}
	}
	cfs.childrenMutex.Lock()
	defer cfs.childrenMutex.Unlock()
	cfs.childrenMap = newChildrenMap
	cfs.rebuildChildren()
}

func (cfs *compositeFileSystem) GetChild(name string) (webdav.FileSystem, bool) {
	cfs.childrenMutex.Lock()
	defer cfs.childrenMutex.Unlock()

	child, ok := cfs.childrenMap[name]
	if !ok {
		return nil, ok
	}
	return child.fs, true
}

func (cfs *compositeFileSystem) rebuildChildren() {
	cfs.children = make(childrenByName, 0, len(cfs.childrenMap))
	for _, c := range cfs.childrenMap {
		cfs.children = append(cfs.children, c)
	}
}

// pathToChild takes the given name and determines if the path is on a child
// filesystem based on the first path component. If it is, this returns the
// remainder of the path minus the first path component, true, and the
// corresponding child. If it is not, this returns the original name, false,
// and a nil *child.
//
// If the first path component identifies an unknown child, this will return
// os.ErrNotExist.
func (cfs *compositeFileSystem) pathToChild(name string) (string, bool, *child, error) {
	pathComponents := strings.Split(strings.Trim(name, "/"), "/")
	cfs.childrenMutex.Lock()
	child, childFound := cfs.childrenMap[strings.Trim(pathComponents[0], "/")]
	cfs.childrenMutex.Unlock()
	if !childFound {
		return name, false, nil, os.ErrNotExist
	}

	switch len(pathComponents) {
	case 1:
		return name, false, child, nil
	default:
		return path.Join(pathComponents[1:]...), true, child, nil
	}
}

func isRoot(name string) bool {
	return name == "/"
}
