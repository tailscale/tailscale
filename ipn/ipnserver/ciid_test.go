// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"fmt"
	"testing"
	"time"
)

func TestCIIDWriteGrants(t *testing.T) {
	s := new(Server)

	if s.ciidWriteAllowed("ciid1", "1000") {
		t.Error("ciidWriteAllowed with no grants = true; want false")
	}

	s.noteCIIDWriteAccess("ciid1", "1000")
	if !s.ciidWriteAllowed("ciid1", "1000") {
		t.Error("ciidWriteAllowed after grant = false; want true")
	}
	if s.ciidWriteAllowed("ciid1", "1001") {
		t.Error("ciidWriteAllowed with wrong uid = true; want false")
	}
	if s.ciidWriteAllowed("ciid2", "1000") {
		t.Error("ciidWriteAllowed with unknown CIID = true; want false")
	}

	// Backdate the grant and verify it no longer applies and that
	// a later note prunes it.
	s.ciidGrants["ciid1"] = ciidGrant{uid: "1000", expiry: time.Now().Add(-time.Second)}
	if s.ciidWriteAllowed("ciid1", "1000") {
		t.Error("ciidWriteAllowed with expired grant = true; want false")
	}
	s.noteCIIDWriteAccess("ciid2", "1000")
	if _, ok := s.ciidGrants["ciid1"]; ok {
		t.Error("expired grant not pruned by noteCIIDWriteAccess")
	}
}

func TestCIIDWriteGrantsBounded(t *testing.T) {
	s := new(Server)
	for i := range maxCIIDGrants {
		s.noteCIIDWriteAccess(fmt.Sprintf("ciid%d", i), "1000")
	}
	s.noteCIIDWriteAccess("one-too-many", "1000")
	if got := len(s.ciidGrants); got != maxCIIDGrants {
		t.Errorf("len(ciidGrants) = %v; want %v", got, maxCIIDGrants)
	}
	if s.ciidWriteAllowed("one-too-many", "1000") {
		t.Error("grant added beyond maxCIIDGrants")
	}
	// Refreshing an existing grant is still allowed at capacity.
	s.noteCIIDWriteAccess("ciid0", "1000")
	if !s.ciidWriteAllowed("ciid0", "1000") {
		t.Error("existing grant not refreshable at capacity")
	}
}
