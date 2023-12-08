// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
)

func (cfs *compositeFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if isRoot(oldName) || isRoot(newName) {
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

	if oldChild == newChild {
		// file is moving within the same child, let the child handle it
		return oldChild.fs.Rename(ctx, oldPath, newPath)
	}

	// file is moving between children, handle as a copy plus delete (not atomic, may leave inconsistent state)
	fi, err := oldChild.fs.Stat(ctx, oldPath)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return os.ErrNotExist
		}
		return err
	}
	if fi.IsDir() {
		// We don't support copying whole directories
		// TODO(oxtoacart): maybe we need a more appropriate error here
		return os.ErrPermission
	}

	old, err := oldChild.fs.OpenFile(ctx, oldPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer old.Close()

	new, err := newChild.fs.OpenFile(ctx, newPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode())
	if err != nil {
		return err
	}
	defer new.Close()

	_, err = io.Copy(new, old)
	return err
}
