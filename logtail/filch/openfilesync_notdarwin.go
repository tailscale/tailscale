// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build !darwin

package filch

import (
	"os"
)

func openFileSync(path string, flag int, perm os.FileMode) (*os.File, error) {
	// TODO(crawshaw): on Linux and FreeBSD, use O_SYNC
	return os.OpenFile(path, flag, perm)
}
