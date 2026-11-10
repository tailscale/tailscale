// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestPeerDialControlContext(t *testing.T) {
	original := peerDialControlFunc
	t.Cleanup(func() { peerDialControlFunc = original })
	for _, enabled := range []bool{false, true} {
		name := "no_hook"
		if enabled {
			name = "platform_hook"
		}
		t.Run(name, func(t *testing.T) {
			d := new(Dialer)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			raw := &struct{ syscall.RawConn }{}
			wantErr := errors.New("platform control failed")
			calls := 0
			peerDialControlFunc = nil
			if enabled {
				peerDialControlFunc = func(got *Dialer) func(context.Context, string, string, syscall.RawConn) error {
					if got != d {
						t.Error("factory received the wrong dialer")
					}
					return func(gotCtx context.Context, network, address string, c syscall.RawConn) error {
						calls++
						if gotCtx != ctx || network != "tcp4" || address != "100.64.0.1:80" || c != raw {
							t.Error("platform hook arguments were not forwarded")
						}
						return wantErr
					}
				}
			}
			// The debug peer dialer uses the public factory directly.
			hook := d.PeerDialControlFunc()
			if (hook != nil) != enabled {
				t.Fatalf("factory hook present = %v; want %v", hook != nil, enabled)
			}
			if hook != nil && hook(ctx, "tcp4", "100.64.0.1:80", raw) != wantErr {
				t.Error("factory hook lost platform error")
			}
			// Normal PeerAPI dialing uses the cached dialer.
			nd := d.getPeerDialer()
			if nd.Control != nil || (nd.ControlContext != nil) != enabled {
				t.Fatal("peer dialer did not use ControlContext exclusively")
			}
			if nd.ControlContext != nil && nd.ControlContext(ctx, "tcp4", "100.64.0.1:80", raw) != wantErr {
				t.Error("peer dialer hook lost platform error")
			}
			if enabled && calls != 2 {
				t.Errorf("hook calls = %d; want 2", calls)
			}
		})
	}
}
