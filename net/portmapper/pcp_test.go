// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"testing"

	"inet.af/netaddr"
)

var examplePCPMapResponse = []byte{2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112, 9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 135, 180, 175, 246}

func TestParsePCPMapResponse(t *testing.T) {
	mapping, err := parsePCPMapResponse(examplePCPMapResponse)
	if err != nil {
		t.Fatalf("failed to parse PCP Map Response: %v", err)
	}
	if mapping == nil {
		t.Fatalf("got nil mapping when expected non-nil")
	}
	expectedAddr := netaddr.MustParseIPPort("135.180.175.246:1234")
	if mapping.external != expectedAddr {
		t.Errorf("mismatched external address, got: %v, want: %v", mapping.external, expectedAddr)
	}
}
