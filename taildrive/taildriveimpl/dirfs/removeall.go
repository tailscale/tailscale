// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dirfs

import (
	"context"
	"os"
)

// RemoveAll implements webdav.File. No removal is supported and this always
// returns os.ErrPermission.
func (dfs *FS) RemoveAll(ctx context.Context, name string) error {
	return &os.PathError{Op: "rm", Path: name, Err: os.ErrPermission}
}
