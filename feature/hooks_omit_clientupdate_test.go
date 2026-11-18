// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_clientupdate

package feature

import "testing"

// Even if something links in the clientupdate package and registers the hook,
// CanAutoUpdate must report false when the feature is omitted from the build.
func TestCanAutoUpdateClientUpdateOmitted(t *testing.T) {
	t.Cleanup(HookCanAutoUpdate.SetForTest(func() bool { return true }))
	if CanAutoUpdate() {
		t.Error("CanAutoUpdate() = true; want false with ts_omit_clientupdate")
	}
}
