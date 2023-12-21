// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"io/fs"

	"tailscale.com/tailfs/shared"
	"tailscale.com/util/pathutil"
)

func (cfs *compositeFileSystem) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	if pathutil.IsRoot(name) {
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

	path, onChild, child, err := cfs.pathToChild(name)
	if err != nil {
		return nil, err
	}

	if !onChild && !cfs.statChildren {
		// Return a read-only FileInfo for this child.
		// Always use now() as the modified time to bust caches.
		return shared.ReadOnlyDirInfo(name, cfs.now()), nil
	}

	fi, err := child.FS.Stat(ctx, path)
	if err != nil {
		return nil, err
	}

	// we use the full name, which is different than what the child sees
	return shared.RenamedFileInfo(ctx, name, fi), nil
}
