// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks5

import (
	"fmt"
	"io"
	"net"
	"testing"

	"golang.org/x/net/proxy"
)

func socks5Server(listener net.Listener) {
	var server Server
	err := server.Serve(listener)
	if err != nil {
		panic(err)
	}
        listener.Close()
}

func backendServer(listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	conn.Write([]byte("Test"))
	conn.Close()
        listener.Close()
}

func TestRead(t *testing.T) {
	// backend server which we'll use SOCKS5 to connect to
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := listener.Addr().(*net.TCPAddr).Port
	go backendServer(listener)

	// SOCKS5 server
	socks5, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go socks5Server(socks5)

	addr := fmt.Sprintf("localhost:%d", socks5Port)
	socksDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
}
