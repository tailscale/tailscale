// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"sync/atomic"
	"testing"

	"tailscale.com/util/eventbus/eventbustest"
)

// A sender can win its select against closed and enqueue after Close has
// drained the injection queue. The sender must then release the packet.
func TestInjectionSendAfterCloseDrain(t *testing.T) {
	_, w := newFakeTUN(t.Logf, eventbustest.NewBus(t), false)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var released atomic.Int32
	w.injectionQueue.ch <- tunInjectedRead{packet: newInjectionTestPacket([]byte{1}, &released)}
	w.drainIfClosed()
	if got := released.Load(); got != 1 {
		t.Fatalf("released %d times, want 1", got)
	}
}
