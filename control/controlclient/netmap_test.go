// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestNetworkMapConcise(t *testing.T) {
	nm := &NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Name:      "foo",
				Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
			},
			{
				Name:      "bar",
				Endpoints: []string{"10.2.0.100:12", "10.1.0.100:12345"},
			},
		},
	}
	var got string
	n := int(testing.AllocsPerRun(1000, func() {
		got = nm.Concise()
	}))
	t.Logf("Allocs = %d", n)
	want := "netmap: self: [AAAAA] auth=machine-unknown :0 []\n" +
		" [AAAAA]                    :    192.168.0.100:12     192.168.0.100:12354\n [AAAAA]                    :       10.2.0.100:12        10.1.0.100:12345\n"
	if got != want {
		t.Errorf("Wrong output\n Got: %q\nWant: %q\n## Got (unescaped):\n%s\n## Want (unescaped):\n%s\n", got, want, got, want)
	}
}
