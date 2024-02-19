// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
	"tailscale.com/util/must"
)

func TestSetUserTimeout(t *testing.T) {
	l := must.Get(nettest.NewLocalListener("tcp"))
	defer l.Close()

	var err error
	if e := must.Get(l.(*net.TCPListener).SyscallConn()).Control(func(fd uintptr) {
		err = SetUserTimeout(fd, 0)
	}); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	v := must.Get(unix.GetsockoptInt(int(must.Get(l.(*net.TCPListener).File()).Fd()), unix.SOL_TCP, unix.TCP_USER_TIMEOUT))
	if v != 0 {
		t.Errorf("TCP_USER_TIMEOUT: got %v; want 0", v)
	}

	if e := must.Get(l.(*net.TCPListener).SyscallConn()).Control(func(fd uintptr) {
		err = SetUserTimeout(fd, 30*time.Second)
	}); e != nil {
		t.Fatal(e)
	}
	if err != nil {
		t.Fatal(err)
	}
	v = must.Get(unix.GetsockoptInt(int(must.Get(l.(*net.TCPListener).File()).Fd()), unix.SOL_TCP, unix.TCP_USER_TIMEOUT))
	if v != 30000 {
		t.Errorf("TCP_USER_TIMEOUT: got %v; want 30000", v)
	}
}
