// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"

	"tailscale.com/util/pathutil"
)

func (cfs *compositeFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if pathutil.IsRoot(oldName) || pathutil.IsRoot(newName) {
		// root directory is read-only
		return os.ErrPermission
	}

	oldPath, oldOnChild, oldChild, err := cfs.pathToChild(oldName)
	if !oldOnChild {
		// children themselves are read-only
		return os.ErrPermission
	}
	if err != nil {
		return err
	}

	newPath, newOnChild, newChild, err := cfs.pathToChild(newName)
	if !newOnChild {
		// children themselves are read-only
		return os.ErrPermission
	}
	if err != nil {
		return err
	}

	if oldChild != newChild {
		// moving a file across children is not permitted
		return os.ErrPermission
	}

	// file is moving within the same child, let the child handle it
	return oldChild.FS.Rename(ctx, oldPath, newPath)
}
