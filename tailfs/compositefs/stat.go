// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"io/fs"

	"tailscale.com/tailfs/shared"
)

// Stat implements webdav.FileSystem.
func (cfs *CompositeFileSystem) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	if shared.IsRoot(name) {
		// Root is a directory
		// always use now() as the modified time to bust caches
		fi := shared.ReadOnlyDirInfo(name, cfs.now())
		if cfs.statChildren {
			// update last modified time based on children
			cfs.childrenMu.Lock()
			children := cfs.children
			cfs.childrenMu.Unlock()
			for i, child := range children {
				childInfo, err := child.FS.Stat(ctx, "/")
				if err != nil {
					return nil, err
				}
				if i == 0 || childInfo.ModTime().After(fi.ModTime()) {
					fi.ModdedTime = childInfo.ModTime()
				}
			}
		}
		return fi, nil
	}

	pathInfo, err := cfs.pathInfoFor(name)
	if err != nil {
		return nil, err
	}

	if pathInfo.refersToChild && !cfs.statChildren {
		// Return a read-only FileInfo for this child.
		// Always use now() as the modified time to bust caches.
		return shared.ReadOnlyDirInfo(name, cfs.now()), nil
	}

	fi, err := pathInfo.child.FS.Stat(ctx, pathInfo.pathOnChild)
	if err != nil {
		return nil, err
	}

	// we use the full name, which is different than what the child sees
	return shared.RenamedFileInfo(ctx, name, fi), nil
}
