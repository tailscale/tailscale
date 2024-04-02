// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirfs

import (
	"context"
	"os"
)

// Rename implements interface webdav.FileSystem. No renaming is supported and
// this always returns os.ErrPermission.
func (dfs *FS) Rename(ctx context.Context, oldName, newName string) error {
	return &os.PathError{Op: "mv", Path: oldName, Err: os.ErrPermission}
}
