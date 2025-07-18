// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package taildrop

import (
	"io"
	"os"
)

// defaultFileOps starts nil on Android; libtailscale will replace it
// with an AndroidFileOps during backend construction.
var defaultFileOps FileOps = nil

func (d DefaultFileOps) OpenWriter(name string, offset int64, perm os.FileMode) (io.WriteCloser, string, error) {
	return nil, "", os.ErrPermission
}

func (d DefaultFileOps) Base(pathOrURI string) string              { return pathOrURI }
func (d DefaultFileOps) Remove(name string) error                  { return os.ErrPermission }
func (d DefaultFileOps) ListDir(dir string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
func (d DefaultFileOps) Rename(oldPathOrURI, newName string) (string, error) {
	return "", os.ErrPermission
}
