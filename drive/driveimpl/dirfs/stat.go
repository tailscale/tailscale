// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirfs

import (
	"context"
	"io/fs"
	"os"

	"tailscale.com/drive/driveimpl/shared"
)

// Stat implements webdav.FileSystem.
func (dfs *FS) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	nameWithoutStaticRoot, isStaticRoot := dfs.trimStaticRoot(name)
	if isStaticRoot || shared.IsRoot(name) {
		// Static root is a directory, always use now() as the modified time to
		// bust caches.
		fi := shared.ReadOnlyDirInfo(name, dfs.now())
		return fi, nil
	}

	child := dfs.childFor(nameWithoutStaticRoot)
	if child == nil {
		return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
	}

	return shared.ReadOnlyDirInfo(name, dfs.now()), nil
}
