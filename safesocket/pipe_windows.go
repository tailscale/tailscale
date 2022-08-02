// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

func connect(s *ConnectionStrategy) (net.Conn, error) {
	pipe, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return nil, err
	}
	return pipe, err
}

func setFlags(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR, 1)
	})
}

// TODO(apenwarr): use named pipes instead of sockets?
//
//	I tried to use winio.ListenPipe() here, but that code is a disaster,
//	built on top of an API that's a disaster. So for now we'll hack it by
//	just always using a TCP session on a fixed port on localhost. As a
//	result, on Windows we ignore the vendor and name strings.
//	NOTE(bradfitz): Jason did a new pipe package: https://go-review.googlesource.com/c/sys/+/299009
func listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	lc := net.ListenConfig{
		Control: setFlags,
	}
	pipe, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, 0, err
	}
	return pipe, uint16(pipe.Addr().(*net.TCPAddr).Port), err
}
