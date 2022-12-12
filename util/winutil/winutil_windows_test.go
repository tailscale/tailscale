// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
