// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailscaleroot embeds VERSION.txt into the binary.
package tailscaleroot

import _ "embed"

// VersionDotTxt is the contents of VERSION.txt. Despite the tempting filename,
// this does not necessarily contain the accurate version number of the build, which
// depends on the branch type and how it was built. To get version information, use
// the version package instead.
//
//go:embed VERSION.txt
var VersionDotTxt string

//go:embed ALPINE.txt
var AlpineDockerTag string

// GoToolchainRev is the git hash from github.com/tailscale/go that this release
// should be built using. It may end in a newline.
//
//go:embed go.toolchain.rev
var GoToolchainRev string
