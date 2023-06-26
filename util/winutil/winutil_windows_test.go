// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"testing"
)

const (
	localSystemSID = "S-1-5-18"
	networkSID     = "S-1-5-2"
)

func TestLookupPseudoUser(t *testing.T) {
	localSystem, err := LookupPseudoUser(localSystemSID)
	if err != nil {
		t.Errorf("LookupPseudoUser(%q) error: %v", localSystemSID, err)
	}
	if localSystem.Gid != localSystemSID {
		t.Errorf("incorrect Gid, got %q, want %q", localSystem.Gid, localSystemSID)
	}
	t.Logf("localSystem: %v", localSystem)

	// networkSID is a built-in known group but not a pseudo-user.
	_, err = LookupPseudoUser(networkSID)
	if err == nil {
		t.Errorf("LookupPseudoUser(%q) unexpectedly succeeded", networkSID)
	}
}
