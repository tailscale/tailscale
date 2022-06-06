// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ios || js
// +build ios js

package magicsock

import "tailscale.com/types/opt"

// All knobs are disabled on iOS and Wasm.
// Further, they're const, so the toolchain can produce smaller binaries.
const (
	debugDisco                       = false
	debugOmitLocalAddresses          = false
	debugUseDerpRouteEnv             = ""
	debugUseDerpRoute       opt.Bool = ""
	logDerpVerbose                   = false
	debugReSTUNStopOnIdle            = false
	debugAlwaysDERP                  = false
)

func inTest() bool { return false }
