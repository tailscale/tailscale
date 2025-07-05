// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package taildrop

func setDefaultFileOps(e *Extension) {
	e.SetFileOps(DefaultFileOps{})
}
