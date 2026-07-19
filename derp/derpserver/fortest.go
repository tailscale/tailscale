// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"tailscale.com/derp"
	"tailscale.com/types/key"
	"tailscale.com/util/testenv"
)

// forTest is an unexported type to hide the test-only methods on
// [Server] from godoc.
type forTest struct{ s *Server }

// ForTest returns a handle to test-only methods on s. The resulting
// type is unexported to make it very obvious in godoc that this is
// not stable API. This method panics if called outside of tests,
// which also centralizes all must-be-in-tests validation.
func (s *Server) ForTest() forTest {
	testenv.AssertInTest()
	return forTest{s}
}

// SetOnClientInfo sets a func to be called with each connecting
// client's key and the ClientInfo it sent. It must be called before
// the server accepts any connections.
func (f forTest) SetOnClientInfo(fn func(key.NodePublic, derp.ClientInfo)) {
	f.s.onClientInfoForTest = fn
}
