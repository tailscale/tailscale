// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package magicsock

import (
	"testing"

	"tailscale.com/envknob"
)

// TS_DEBUG_DONT_FRAGMENT keeps the don't-fragment bit on the sockets with path MTU discovery off, through UpdatePMTUD and a rebind, and without it they stay without.
func TestDontFragmentKnob(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_ENABLE_PMTUD", "false")
	for _, on := range []bool{false, true} {
		envknob.SetenvForTest(t, "TS_DEBUG_DONT_FRAGMENT", map[bool]string{false: "", true: "true"}[on])
		c := newTestConn(t)
		check := func(when string) {
			t.Helper()
			checked := 0
			for _, network := range []string{"udp4", "udp6"} {
				df, err := c.getDontFragment(network)
				if err == errUnsupportedConnType {
					continue
				}
				if err != nil {
					t.Fatalf("%s: getDontFragment(%s): %v", when, network, err)
				}
				if df != on {
					t.Errorf("knob %v, %s: %s don't-fragment is %v", on, when, network, df)
				}
				checked++
			}
			if checked == 0 {
				t.Fatalf("%s: neither socket is a UDP socket, so nothing was checked", when)
			}
		}
		check("after NewConn")
		c.UpdatePMTUD()
		check("after UpdatePMTUD")
		if err := c.rebind(dropCurrentPort); err != nil {
			t.Fatal(err)
		}
		check("after a rebind")
		c.Close()
	}
}
