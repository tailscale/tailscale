// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"
)

func (cfs *compositeFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if isRoot(name) {
		// root directory is read-only
		return os.ErrPermission
	}

	path, onChild, child, err := cfs.pathToChild(name)
	if !onChild {
		// children can't be made
		return os.ErrPermission
	}

	if err != nil {
		return err
	}

	return child.fs.Mkdir(ctx, path, perm)
}
