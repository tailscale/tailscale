// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
