// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package logpolicy

import (
	"io"
)

func maybeWrapForPlatform(lw io.Writer, cmdName, logID string) io.Writer {
	return lw
}
