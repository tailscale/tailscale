// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailscaleroot embeds VERSION.txt into the binary.
package tailscaleroot

import _ "embed"

//go:embed VERSION.txt
var Version string

//go:embed ALPINE.txt
var AlpineDockerTag string

// GoToolchainRev is the git hash from github.com/tailscale/go that this release
// should be built using. It may end in a newline.
//
//go:embed go.toolchain.rev
var GoToolchainRev string
