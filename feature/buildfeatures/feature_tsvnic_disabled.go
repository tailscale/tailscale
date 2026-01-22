// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_include_tsvnic

package buildfeatures

// HasTSVNIC is whether the binary was built with support for modular feature "Experimental Windows driver".
// Specifically, it's whether the binary was built with the "ts_include_tsvnic" build tag.
// It's a const so it can be used for dead code elimination.
const HasTSVNIC = false
