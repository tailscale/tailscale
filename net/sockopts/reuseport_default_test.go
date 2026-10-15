// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package sockopts

import (
	"testing"

	"tailscale.com/tstest"
)

func TestBindUDPGroupUnsupported(t *testing.T) {
	var tc testControl
	var log tstest.MemLogger
	pconns, boundPort, err := BindUDPGroup(t.Context(), log.Logf, 4, tc.control, "udp4", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closeConns(pconns)
	wantSharedPort(t, pconns, boundPort, 1)
	wantLines(t, &log, 0)
}
