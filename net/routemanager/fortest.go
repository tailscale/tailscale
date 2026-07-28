// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routemanager

import "tailscale.com/util/testenv"

// forTest is an unexported type to hide the test-only methods on
// [RouteManager] from godoc.
type forTest struct{ rm *RouteManager }

// ForTest returns a handle to test-only methods on rm. The resulting
// type is unexported to make it very obvious in godoc that this is
// not stable API. This method panics if called outside of tests,
// which also centralizes all must-be-in-tests validation.
func (rm *RouteManager) ForTest() forTest {
	testenv.AssertInTest()
	return forTest{rm}
}

// PeerCount returns the number of peers currently tracked. Callers
// must serialize it with mutations like any other write-path access.
func (f forTest) PeerCount() int { return len(f.rm.peers) }
