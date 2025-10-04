// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_debug

package wgengine

import (
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/wgengine/filter"
)

type flowtrackTuple = struct{}

type pendingOpenFlow struct{}

func (*userspaceEngine) trackOpenPreFilterIn(pp *packet.Parsed, t *tstun.Wrapper) (res filter.Response) {
	panic("unreachable")
}

func (*userspaceEngine) trackOpenPostFilterOut(pp *packet.Parsed, t *tstun.Wrapper) (res filter.Response) {
	panic("unreachable")
}
