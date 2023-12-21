// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package tailfs provides a filesystem that allows sharing folders between
// Tailscale nodes using WebDAV.
package tailfs

import (
	"time"
)

const (
	// statCacheTTL causes the local WebDAV proxy to cache file metadata to
	// avoid excessive network roundtrips. This is similar to the
	// DirectoryCacheLifetime setting of Windows' built-in SMB client,
	// see https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/ff686200(v=ws.10)
	statCacheTTL = 10 * time.Second
)
