// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"os"

	"tailscale.com/util/pathutil"
)

func (cfs *compositeFileSystem) RemoveAll(ctx context.Context, name string) error {
	if pathutil.IsRoot(name) {
		// root directory is read-only
		return os.ErrPermission
	}

	path, onChild, child, err := cfs.pathToChild(name)
	if !onChild {
		// children can't be removed
		return os.ErrPermission
	}

	if err != nil {
		return err
	}

	return child.FS.RemoveAll(ctx, path)
}
