// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
//
// The netns package also handles connecting via SOCKS proxies when
// configured by the environment.
package netns

import (
	"flag"
	"testing"
)

var extNetwork = flag.Bool("use-external-network", false, "use the external network in tests")

func TestDial(t *testing.T) {
	if !*extNetwork {
		t.Skip("skipping test without --use-external-network")
	}
	d := NewDialer()
	c, err := d.Dial("tcp", "google.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Logf("got addr %v", c.RemoteAddr())

	c, err = d.Dial("tcp4", "google.com:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Logf("got addr %v", c.RemoteAddr())
}
