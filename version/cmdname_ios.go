// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (go1.16 && ios) || (!go1.16 && darwin && arm64)
// +build go1.16,ios !go1.16,darwin,arm64

package version

import (
	"os"
)

func CmdName() string {
	e, err := os.Executable()
	if err != nil {
		return "cmd"
	}
	return e
}
