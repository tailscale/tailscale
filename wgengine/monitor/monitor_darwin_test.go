// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/net/route"
)

func TestIssue1416RIB(t *testing.T) {
	const ribHex = `32 00 05 10 30 00 00 00 00 00 00 00 04 00 00 00 14 12 04 00 06 03 06 00 65 6e 30 ac 87 a3 19 7f 82 00 00 00 0e 12 00 00 00 00 06 00 91 e0 f0 01 00 00`
	rtmMsg, err := hex.DecodeString(strings.ReplaceAll(ribHex, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rtmMsg)
	if err != nil {
		t.Logf("ParseRIB: %v", err)
		t.Skip("skipping on known failure; see https://github.com/tailscale/tailscale/issues/1416")
		t.Fatal(err)
	}
	t.Logf("Got: %#v", msgs)
}
