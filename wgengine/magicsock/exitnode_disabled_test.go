// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_exitnodehealth || ts_omit_health || ts_omit_useexitnode

package magicsock

import (
	"testing"

	"tailscale.com/types/key"
)

func TestExitNodeReportsOmitted(t *testing.T) {
	// Empty functions must not even dereference nil receivers.
	var de *endpoint
	de.reportExitNodeHeartbeatStateLocked()
	de.checkExitNodeResponsiveness()
	var c *Conn
	c.reportExitNodePong(key.NodePublic{}, 0)
}
