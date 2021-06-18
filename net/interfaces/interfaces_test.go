// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"encoding/json"
	"testing"

	"inet.af/netaddr"
)

func TestGetState(t *testing.T) {
	st, err := GetState()
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.MarshalIndent(st, "", "\t")
	if err != nil {
		t.Errorf("JSON: %v", err)
	}
	t.Logf("Got: %s", j)
	t.Logf("As string: %s", st)

	st2, err := GetState()
	if err != nil {
		t.Fatal(err)
	}

	if !st.EqualFiltered(st2, FilterAll) {
		// let's assume nobody was changing the system network interfaces between
		// the two GetState calls.
		t.Fatal("two States back-to-back were not equal")
	}

	t.Logf("As string:\n\t%s", st)
}

func TestLikelyHomeRouterIP(t *testing.T) {
	gw, my, ok := LikelyHomeRouterIP()
	if !ok {
		t.Logf("no result")
		return
	}
	t.Logf("myIP = %v; gw = %v", my, gw)
}

func TestIsUsableV6(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"first ULA", "fc00::1", true},
		{"Tailscale", "fd7a:115c:a1e0::1", false},
		{"Cloud Run", "fddf:3978:feb1:d745::1", true},
		{"zeros", "0000:0000:0000:0000:0000:0000:0000:0000", false},
		{"Link Local", "fe80::1", false},
		{"Global", "2602::1", true},
	}

	for _, test := range tests {
		if got := isUsableV6(netaddr.MustParseIP(test.ip)); got != test.want {
			t.Errorf("isUsableV6(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}
