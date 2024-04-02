// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirfs

import (
	"context"
	"io/fs"
	"os"

	"github.com/tailscale/xnet/webdav"
	"tailscale.com/drive/driveimpl/shared"
)

// OpenFile implements interface webdav.Filesystem.
func (dfs *FS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	_, isStaticRoot := dfs.trimStaticRoot(name)
	if !isStaticRoot && !shared.IsRoot(name) {
		// Show a folder with no children to represent the requested child. In
		// practice, the children of this folder are never read, we just need
		// to give webdav a file here which it uses to call file.Stat(). So,
		// even though the Child may in fact have its own children, it doesn't
		// matter here.
		return &shared.DirFile{
			Info: shared.ReadOnlyDirInfo(name, dfs.now()),
			LoadChildren: func() ([]fs.FileInfo, error) {
				return nil, nil
			},
		}, nil
	}

	di, err := dfs.Stat(ctx, name)
	if err != nil {
		return nil, err
	}

	if dfs.StaticRoot != "" && !isStaticRoot {
		// Show a folder with a single subfolder that is the static root.
		return &shared.DirFile{
			Info: di,
			LoadChildren: func() ([]fs.FileInfo, error) {
				return []fs.FileInfo{
					shared.ReadOnlyDirInfo(dfs.StaticRoot, dfs.now()),
				}, nil
			},
		}, nil
	}

	// Show a folder with one subfolder for each Child of this FS.
	return &shared.DirFile{
		Info: di,
		LoadChildren: func() ([]fs.FileInfo, error) {
			childInfos := make([]fs.FileInfo, 0, len(dfs.Children))
			for _, c := range dfs.Children {
				if c.isAvailable() {
					childInfo := shared.ReadOnlyDirInfo(c.Name, dfs.now())
					childInfos = append(childInfos, childInfo)
				}
			}
			return childInfos, nil
		},
	}, nil
}
