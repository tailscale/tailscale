// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_exitnodehealth || ts_omit_health || ts_omit_useexitnode

package magicsock

import (
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

func (*endpoint) reportExitNodeHeartbeatStateLocked()      {}
func (*endpoint) checkExitNodeResponsiveness()             {}
func (*Conn) reportExitNodePong(key.NodePublic, mono.Time) {}
