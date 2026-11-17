// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sockopts

import (
	"testing"

	"golang.org/x/sys/unix"
	"tailscale.com/tstest"
)

func TestBindUDPGroup(t *testing.T) {
	for _, tt := range []struct {
		name    string
		sockets int // passed to BindUDPGroup
		failAt  int // bind at which the Control hook starts failing

		wantSockets   int
		wantReusePort bool
		wantLines     int
		wantErr       bool
	}{
		{name: "full", sockets: 4, wantSockets: 4, wantReusePort: true},
		{name: "short", sockets: 4, failAt: 3, wantSockets: 2, wantReusePort: true, wantLines: 1},
		{name: "lone", sockets: 1, wantSockets: 1},
		{name: "unbindable", sockets: 4, failAt: 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := testControl{failAt: tt.failAt}
			var log tstest.MemLogger

			pconns, boundPort, err := BindUDPGroup(t.Context(), log.Logf, tt.sockets, tc.control, "udp4", 0)
			defer closeConns(pconns)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("BindUDPGroup err = %v, want an error: %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if pconns != nil {
					t.Errorf("returned %d sockets, want none", len(pconns))
				}
				return
			}
			wantSharedPort(t, pconns, boundPort, tt.wantSockets)
			for i, pconn := range pconns {
				rc, err := RawConn(pconn)
				if err != nil {
					t.Fatalf("socket %d: %v", i, err)
				}
				var val int
				var serr error
				if err := rc.Control(func(fd uintptr) {
					val, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
				}); err != nil {
					t.Fatalf("socket %d: %v", i, err)
				}
				if serr != nil {
					t.Fatalf("socket %d: getsockopt(SO_REUSEPORT): %v", i, serr)
				}
				if got := val == 1; got != tt.wantReusePort {
					t.Errorf("socket %d: SO_REUSEPORT = %v, want %v", i, got, tt.wantReusePort)
				}
			}
			wantLines(t, &log, tt.wantLines)
		})
	}
}
