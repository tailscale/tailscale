// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package compositefs

import (
	"context"
	"io/fs"

	"tailscale.com/tailfs/shared"
)

func (cfs *compositeFileSystem) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	cfs.logf("ZZZZ compositefs stat %v", name)
	if isRoot(name) {
		// Root is a directory
		cfs.logf("ZZZZ compositefs stat root")
		return shared.ReadOnlyDirInfo(name), nil
	}

	path, onChild, child, err := cfs.pathToChild(name)
	if err != nil {
		cfs.logf("ZZZZ compositefs can't get pathToChild: %v", err)
		return nil, err
	}

	if !onChild {
		cfs.logf("ZZZZ compositefs stat child")
		// This means name refers to a child itself rather than a file on a child
		return shared.ReadOnlyDirInfo(name), nil
	}

	cfs.logf("ZZZZ compositefs will actually stat %v", path)
	fi, err := child.fs.Stat(ctx, path)
	if err != nil {
		cfs.logf("ZZZZ compositefs stat failed %v", err)
		return nil, err
	}

	return &shared.StaticFileInfo{
		Named:    name, // we use the full name, which is different than what the child sees
		Sized:    fi.Size(),
		Moded:    fi.Mode(),
		ModTimed: fi.ModTime(),
		Dir:      fi.IsDir(),
	}, nil
}
