// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"flag"
	"testing"

	"tailscale.com/tailcfg"
)

var external = flag.Bool("external", false, "run external network tests")

func TestPopulateNetworkConditions(t *testing.T) {
	if !*external {
		t.Skip("skipping network test without -external flag")
	}
	b := &LocalBackend{logf: t.Logf}
	hi := new(tailcfg.Hostinfo)
	b.populateNetworkConditions(hi)
	t.Logf("Got: %+v", hi)

}
