// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_macext && (darwin || ios)

package tsdial

import (
	"strings"
	"testing"
)

func TestPeerDialControlMissingInterface(t *testing.T) {
	hook := peerDialControlFuncNetworkExtension(new(Dialer))
	if err := hook(t.Context(), "tcp4", "100.64.0.1:80", nil); err == nil || !strings.Contains(err.Error(), "failed to find TUN interface") {
		t.Errorf("hook error = %v; want missing peer interface", err)
	}
}
