// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_drive_magic

package driveimpl

import (
	"net/http"

	"tailscale.com/drive"
)

// maybeServeMagic is a stub for builds without the magic-share feature.
// It never claims the request, so a share named "magic" is served as a
// regular share with no name-encoded ACL semantics.
func (s *FileSystemForRemote) maybeServeMagic(authz drive.Authz, share *drive.Share, pathComponents []string, w http.ResponseWriter, r *http.Request) bool {
	return false
}
