// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

// All knobs are disabled on iOS.
// Further, they're const, so the toolchain can produce smaller binaries.
const (
	debugDisco              = false
	debugOmitLocalAddresses = false
	debugUseDerpRouteEnv    = ""
	debugUseDerpRoute       = false
	logDerpVerbose          = false
	debugReSTUNStopOnIdle   = false
	debugAlwaysDERP         = false
)

func inTest() bool { return false }
