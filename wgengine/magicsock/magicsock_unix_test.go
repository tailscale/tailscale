// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package magicsock

import (
	"net"
	"syscall"
	"testing"

	"tailscale.com/types/nettype"
)

func TestTrySetSocketBuffer(t *testing.T) {
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rc, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	getBufs := func() (int, int) {
		var rcv, snd int
		rc.Control(func(fd uintptr) {
			rcv, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
			if err != nil {
				t.Errorf("getsockopt(SO_RCVBUF): %v", err)
			}
			snd, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
			if err != nil {
				t.Errorf("getsockopt(SO_SNDBUF): %v", err)
			}
		})
		return rcv, snd
	}

	curRcv, curSnd := getBufs()

	trySetSocketBuffer(c.(nettype.PacketConn), t.Logf)

	newRcv, newSnd := getBufs()

	if curRcv > newRcv {
		t.Errorf("SO_RCVBUF decreased: %v -> %v", curRcv, newRcv)
	}
	if curSnd > newSnd {
		t.Errorf("SO_SNDBUF decreased: %v -> %v", curSnd, newSnd)
	}

	// On many systems we may not increase the value, particularly running as a
	// regular user, so log the information for manual verification.
	t.Logf("SO_RCVBUF: %v -> %v", curRcv, newRcv)
	t.Logf("SO_SNDBUF: %v -> %v", curRcv, newRcv)
}
