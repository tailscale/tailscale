// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package metrics

import "testing"

func TestCurrentFDsFast(t *testing.T) {
	fast, ok := currentFDsFast()
	if !ok {
		t.Skip("fast path unavailable; kernel older than 6.2")
	}
	// The dirwalk count includes the directory file descriptor that
	// the walk itself has open, so it reports one more than the fast
	// path does.
	slow := currentFDsDirwalk() - 1
	if fast != slow {
		t.Errorf("currentFDsFast = %v; currentFDsDirwalk-1 = %v", fast, slow)
	}
}
