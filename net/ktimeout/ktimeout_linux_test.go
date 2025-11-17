// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/util/must"
)

func TestSetUserTimeout(t *testing.T) {
	lc := net.ListenConfig{}
	// As of 2025-02-19, MPTCP does not support TCP_USER_TIMEOUT socket option
	// set in ktimeout.UserTimeout above.
	lc.SetMultipathTCP(false)

	ln := must.Get(lc.Listen(context.Background(), "tcp", "localhost:0"))
	defer ln.Close()

	var err error
	if e := must.Get(ln.(*net.TCPListener).SyscallConn()).Control(func(fd uintptr) {
		err = SetUserTimeout(fd, 0)
	}); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	v := must.Get(unix.GetsockoptInt(int(must.Get(ln.(*net.TCPListener).File()).Fd()), unix.SOL_TCP, unix.TCP_USER_TIMEOUT))
	if v != 0 {
		t.Errorf("TCP_USER_TIMEOUT: got %v; want 0", v)
	}

	if e := must.Get(ln.(*net.TCPListener).SyscallConn()).Control(func(fd uintptr) {
		err = SetUserTimeout(fd, 30*time.Second)
	}); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	v = must.Get(unix.GetsockoptInt(int(must.Get(ln.(*net.TCPListener).File()).Fd()), unix.SOL_TCP, unix.TCP_USER_TIMEOUT))
	if v != 30000 {
		t.Errorf("TCP_USER_TIMEOUT: got %v; want 30000", v)
	}
}
