// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"testing"

	"tailscale.com/control/controlclient"
)

func checkPrefs(t *testing.T, p Prefs) {
	var err error
	var p2, p2c Prefs
	var p2b Prefs

	pp := p.Pretty()
	if pp == "" {
		t.Fatalf("default p.Pretty() failed\n")
	}
	t.Logf("\npp:   %#v\n", pp)
	b := p.ToBytes()
	if len(b) == 0 {
		t.Fatalf("default p.ToBytes() failed\n")
	}
	if p != p {
		t.Fatalf("p != p\n")
	}
	p2 = p
	p2.RouteAll = true
	if p == p2 {
		t.Fatalf("p == p2\n")
	}
	p2b, err = PrefsFromBytes(p2.ToBytes(), false)
	if err != nil {
		t.Fatalf("PrefsFromBytes(p2) failed\n")
	}
	p2p := p2.Pretty()
	p2bp := p2b.Pretty()
	t.Logf("\np2p:  %#v\np2bp: %#v\n", p2p, p2bp)
	if p2p != p2bp {
		t.Fatalf("p2p != p2bp\n%#v\n%#v\n", p2p, p2bp)
	}
	if !p2.Equals(&p2b) {
		t.Fatalf("p2 != p2b\n%#v\n%#v\n", p2, p2b)
	}
	p2c = *p2.Copy()
	if !p2b.Equals(&p2c) {
		t.Fatalf("p2b != p2c\n")
	}
}

func TestBasicPrefs(t *testing.T) {
	p := Prefs{}
	checkPrefs(t, p)
}

func TestPrefsPersist(t *testing.T) {
	c := controlclient.Persist{
		LoginName: "test@example.com",
	}
	p := Prefs{
		CorpDNS: true,
		Persist: &c,
	}
	checkPrefs(t, p)
}
