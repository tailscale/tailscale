// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !ts_omit_hujsonconf

package source

import "github.com/tailscale/hujson"

// Only link the hujson package on platforms that use it, to reduce binary
// size & memory a bit. iOS and Android don't load syspolicy files from
// disk so they don't need HuJSON either.
//
// While the linker's deadcode mostly handles this today, this keeps us
// honest for the future.

func init() {
	hujsonStandardize = hujson.Standardize
}
