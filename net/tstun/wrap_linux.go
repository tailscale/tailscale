// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"runtime"
)

// SetLinkFeaturesPostUp configures link features on t based on select TS_TUN_
// environment variables and OS feature tests. Callers should ensure t is
// up prior to calling, otherwise OS feature tests may be inconclusive.
func (t *Wrapper) SetLinkFeaturesPostUp() {
	if t.isTAP || runtime.GOOS == "android" {
		return
	}
}
