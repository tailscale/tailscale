// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"

	"tailscale.com/tailfs/shared"
)

// Rename implements interface webdav.FileSystem. The root of this file system
// is read-only, so any attempt to rename a child within the root of this
// filesystem will fail with os.ErrPermission. Renaming across children is not
// supported and will fail with os.ErrPermission. Renaming within a child will
// be handled by the respective child.
func (cfs *CompositeFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if shared.IsRoot(oldName) || shared.IsRoot(newName) {
		// root directory is read-only
		return os.ErrPermission
	}

	oldPathInfo, err := cfs.pathInfoFor(oldName)
	if oldPathInfo.refersToChild {
		// children themselves are read-only
		return os.ErrPermission
	}
	if err != nil {
		return err
	}

	newPathInfo, err := cfs.pathInfoFor(newName)
	if newPathInfo.refersToChild {
		// children themselves are read-only
		return os.ErrPermission
	}
	if err != nil {
		return err
	}

	if oldPathInfo.child != newPathInfo.child {
		// moving a file across children is not permitted
		return os.ErrPermission
	}

	// file is moving within the same child, let the child handle it
	return oldPathInfo.child.FS.Rename(ctx, oldPathInfo.pathOnChild, newPathInfo.pathOnChild)
}
