// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tailscaleroot embeds VERSION.txt into the binary.
package tailscaleroot

import _ "embed"

//go:embed VERSION.txt
var Version string
