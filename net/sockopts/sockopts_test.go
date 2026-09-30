// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sockopts

import (
	"errors"
	"net"
	"testing"

	"tailscale.com/types/nettype"
)

// udpConns returns n bound UDP sockets, closed when the test ends.
func udpConns(t *testing.T, n int) []nettype.PacketConn {
	t.Helper()
	pconns := make([]nettype.PacketConn, n)
	for i := range pconns {
		uc, err := net.ListenUDP("udp4", nil)
		if err != nil {
			t.Fatalf("listen udp4: %v", err)
		}
		t.Cleanup(func() { uc.Close() })
		pconns[i] = uc
	}
	return pconns
}

func TestControlEach(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var calls int
		err := ControlEach(nil, func(uintptr) error { calls++; return nil })
		if !errors.Is(err, ErrNoSocket) {
			t.Errorf("err = %v, want it to wrap %v", err, ErrNoSocket)
		}
		if calls != 0 {
			t.Errorf("fn called %d times, want 0", calls)
		}
	})

	t.Run("nosocket", func(t *testing.T) {
		type noSocketConn struct{ nettype.PacketConn } // mask syscall.Conn
		const sockets = 3
		for bad := range sockets {
			pconns := udpConns(t, sockets)
			pconns[bad] = noSocketConn{}
			var calls int
			err := ControlEach(pconns, func(uintptr) error { calls++; return nil })
			if !errors.Is(err, ErrNoSocket) {
				t.Errorf("bad=%d: err = %v, want it to wrap %v", bad, err, ErrNoSocket)
			}
			if calls != 0 {
				t.Errorf("bad=%d: fn called %d times, want 0", bad, calls)
			}
		}
	})

	t.Run("eachsocket", func(t *testing.T) {
		const sockets = 4
		pconns := udpConns(t, sockets)
		wantErr := errors.New("boom")
		// failAt == sockets doesn't fail.
		for failAt := range sockets + 1 {
			var calls int
			err := ControlEach(pconns, func(uintptr) error {
				defer func() { calls++ }()
				if calls == failAt {
					return wantErr
				}
				return nil
			})
			if calls != sockets {
				t.Errorf("failAt=%d: fn called %d times, want %d", failAt, calls, sockets)
			}
			if failAt == sockets {
				if err != nil {
					t.Errorf("all sockets succeeded, but err = %v", err)
				}
				continue
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("failAt=%d: err = %v, want it to wrap %v", failAt, err, wantErr)
			}
			if errors.Is(err, ErrNoSocket) {
				t.Errorf("failAt=%d: err = %v, want it not to match %v", failAt, err, ErrNoSocket)
			}
		}
	})
}
