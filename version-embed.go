// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
