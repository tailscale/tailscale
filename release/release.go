// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package release provides functionality for building client releases.
package release

import "embed"

// This contains all files in the release directory,
// notably the files needed for deb, rpm, and similar packages.
// Because we assign this to the blank identifier, it does not actually embed the files.
// However, this does cause `go mod vendor` to include the files when vendoring the package.
//
//go:embed *
var _ embed.FS
