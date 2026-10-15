// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package sockopts

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/types/nettype"
)

var errListen = errors.New("test listen failure")

type testControl struct {
	// failAt is the 1-based bind at which control starts returning errListen.
	// Zero never fails.
	failAt int

	calls int
}

func (tc *testControl) control(_, _ string, _ syscall.RawConn) error {
	tc.calls++
	if tc.failAt != 0 && tc.calls >= tc.failAt {
		return errListen
	}
	return nil
}

func wantLines(t *testing.T, log *tstest.MemLogger, want int) {
	t.Helper()
	if got := strings.Count(log.String(), "\n"); got != want {
		t.Errorf("logged %d lines, want %d: %q", got, want, log.String())
	}
}

func closeConns(pconns []nettype.PacketConn) {
	for _, pconn := range pconns {
		pconn.Close()
	}
}

func wantSharedPort(t *testing.T, pconns []nettype.PacketConn, boundPort uint16, want int) {
	t.Helper()
	if got := len(pconns); got != want {
		t.Fatalf("bound %d sockets, want %d", got, want)
	}
	if boundPort == 0 {
		t.Error("boundPort is zero")
	}
	for i, pconn := range pconns {
		if got := uint16(pconn.LocalAddr().(*net.UDPAddr).Port); got != boundPort {
			t.Errorf("socket %d bound to port %d, want %d", i, got, boundPort)
		}
	}
}

func TestBindUDPGroupError(t *testing.T) {
	for _, tt := range []struct {
		name    string
		failAt  int // bind at which the Control hook starts failing
		network string

		wantErr error // unwrapped from the returned error, if non-nil
	}{
		{name: "control-fails", failAt: 1, network: "udp4", wantErr: errListen},
		{name: "bad-network", network: "tcp4"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := testControl{failAt: tt.failAt}
			var log tstest.MemLogger

			pconns, boundPort, err := BindUDPGroup(t.Context(), log.Logf, 4, tc.control, tt.network, 0)
			defer closeConns(pconns)
			if err == nil {
				t.Fatal("BindUDPGroup succeeded, want an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want it to wrap %v", err, tt.wantErr)
			}
			if pconns != nil {
				t.Errorf("returned %d sockets, want none", len(pconns))
			}
			if boundPort != 0 {
				t.Errorf("boundPort = %d, want 0", boundPort)
			}
			wantLines(t, &log, 0)
		})
	}
}
