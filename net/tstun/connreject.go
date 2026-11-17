// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_connreject

package tstun

import (
	"tailscale.com/net/connreject"
	"tailscale.com/net/packet"
	"tailscale.com/syncs"
)

// connRejectState holds the connreject feature's per-Wrapper storage.
// Its definition only references [tailscale.com/net/connreject] when
// the feature is built in; see connreject_stub.go for the no-op
// counterpart used under -tags ts_omit_connreject.
type connRejectState struct {
	cb syncs.AtomicValue[func(connreject.Event)]
}

// SetConnRejectCallback installs a callback that is invoked when the
// Wrapper emits an outbound TSMP reject for an inbound peer connection
// that was dropped by the packet filter. The callback receives a fully
// populated [connreject.Event] of [connreject.Incoming] direction.
//
// A nil fn unsets any previously installed callback.
func (t *Wrapper) SetConnRejectCallback(fn func(connreject.Event)) {
	t.connReject.cb.Store(fn)
}

// notifyConnRejectTSMPSent delivers an Incoming-direction event to the
// installed callback, if any, derived from a TSMP reject we just
// injected outbound.
func (t *Wrapper) notifyConnRejectTSMPSent(rj packet.TailscaleRejectedHeader) {
	fn := t.connReject.cb.Load()
	if fn == nil {
		return
	}
	reason := connreject.ReasonACL
	if rj.Reason == packet.RejectedDueToShieldsUp {
		reason = connreject.ReasonShields
	}
	fn(connreject.Event{
		Direction: connreject.Incoming,
		Proto:     rj.Proto,
		Src:       rj.Src,
		Dst:       rj.Dst,
		Reason:    reason,
		Source:    connreject.SourceTSMPSent,
	})
}
