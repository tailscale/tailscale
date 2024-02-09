// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"

	"tailscale.com/tailfs/tailfsimpl/shared"
)

// RemoveAll implements webdav.File. The root of this file system is read-only,
// so attempting to call RemoveAll on the root will fail with os.ErrPermission.
// RemoveAll within a child will be handled by the respective child.
func (cfs *CompositeFileSystem) RemoveAll(ctx context.Context, name string) error {
	if shared.IsRoot(name) {
		// root directory is read-only
		return os.ErrPermission
	}

	pathInfo, err := cfs.pathInfoFor(name)
	if pathInfo.refersToChild {
		// children can't be removed
		return os.ErrPermission
	}

	if err != nil {
		return err
	}

	return pathInfo.child.FS.RemoveAll(ctx, pathInfo.pathOnChild)
}
