// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_connreject

package wgengine

import (
	"tailscale.com/net/connreject"
	"tailscale.com/syncs"
)

// connRejectState holds the connreject feature's per-engine storage.
// Its definition only references [tailscale.com/net/connreject] when
// the feature is built in; see connreject_stub.go for the no-op
// counterpart used under -tags ts_omit_connreject.
type connRejectState struct {
	cb syncs.AtomicValue[func(connreject.Event)]
}

// SetConnRejectCallback installs a callback invoked when the engine
// observes an outbound-direction connection rejection (an inbound TSMP
// reject from a peer or a pendopen timeout). Passing nil uninstalls a
// previously installed callback.
//
// The method is intentionally not declared on the [Engine] interface
// so min builds do not pull in [tailscale.com/net/connreject].
func (e *userspaceEngine) SetConnRejectCallback(fn func(connreject.Event)) {
	e.connReject.cb.Store(fn)
}
