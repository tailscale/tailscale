// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

package hostinfo

import (
	"os"
	"path/filepath"
)

func init() {
	packageType = packageTypeDarwin
}

func packageTypeDarwin() string {
	// Using tailscaled or IPNExtension?
	exe, _ := os.Executable()
	return filepath.Base(exe)
}
