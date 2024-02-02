// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"

	"tailscale.com/tailfs/shared"
)

// Mkdir implements webdav.Filesystem. The root of this file system is
// read-only, so any attempts to make directories within the root will fail
// with os.ErrPermission. Attempts to make directories within one of the child
// filesystems will be handled by the respective child.
func (cfs *CompositeFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if shared.IsRoot(name) {
		// root directory already exists, consider this okay
		return nil
	}

	pathInfo, err := cfs.pathInfoFor(name)
	if pathInfo.refersToChild {
		// children can't be made
		if pathInfo.child != nil {
			// since child already exists, consider this okay
			return nil
		}
		// since child doesn't exist, return permission error
		return os.ErrPermission
	}

	if err != nil {
		return err
	}

	return pathInfo.child.FS.Mkdir(ctx, pathInfo.pathOnChild, perm)
}
