// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"context"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketMarkWorks(t *testing.T) {
	_ = socketMarkWorks()
	// we cannot actually assert whether the test runner has SO_MARK available
	// or not, as we don't know. We're just checking that it doesn't panic.
}

func TestSetListenConfigInterfaceName(t *testing.T) {
	// Setting SO_BINDTODEVICE requires CAP_NET_RAW, which the test
	// runner has when running as root and may or may not have otherwise.
	if os.Geteuid() != 0 {
		t.Skip("skipping; setting SO_BINDTODEVICE requires CAP_NET_RAW")
	}

	var lc net.ListenConfig
	if err := SetListenConfigInterfaceName(&lc, "lo"); err != nil {
		t.Fatal(err)
	}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("got listener of type %T, want *net.TCPListener", ln)
	}
	rc, err := tcpLn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got string
	var sockErr error
	err = rc.Control(func(fd uintptr) {
		got, sockErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	})
	if err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("getsockopt SO_BINDTODEVICE: %v", sockErr)
	}
	if got != "lo" {
		t.Errorf("SO_BINDTODEVICE = %q, want %q", got, "lo")
	}
}
