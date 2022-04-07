// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"math"
	"testing"

	"tailscale.com/tailcfg"
)

// maxAllowedNoiseVersion is the highest we expect the Tailscale
// capability version to ever get. It's a value close to 2^16, but
// with enough leeway that we get a very early warning that it's time
// to rework the wire protocol to allow larger versions, while still
// giving us headroom to bump this test and fix the build.
//
// Code elsewhere in the client will panic() if the tailcfg capability
// version exceeds 16 bits, so take a failure of this test seriously.
const maxAllowedNoiseVersion = math.MaxUint16 - 5000

func TestNoiseVersion(t *testing.T) {
	if tailcfg.CurrentCapabilityVersion > maxAllowedNoiseVersion {
		t.Fatalf("tailcfg.CurrentCapabilityVersion is %d, want <=%d", tailcfg.CurrentCapabilityVersion, maxAllowedNoiseVersion)
	}
}
