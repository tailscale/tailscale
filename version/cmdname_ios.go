// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ios

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
