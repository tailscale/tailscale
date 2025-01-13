// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package atomicfile

import (
	"os"
)

func rename(srcFile, destFile string) error {
	return os.Rename(srcFile, destFile)
}
