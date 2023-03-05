// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"errors"
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

func TestReadPassword(t *testing.T) {
	// backend server which we'll use SOCKS5 to connect to
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := ln.Addr().(*net.TCPAddr).Port
	go backendServer(ln)

	socks5ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		socks5ln.Close()
	})
	auth := &proxy.Auth{User: "foo", Password: "bar"}
	go func() {
		s := Server{Username: auth.User, Password: auth.Password}
		err := s.Serve(socks5ln)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	addr := fmt.Sprintf("localhost:%d", socks5ln.Addr().(*net.TCPAddr).Port)

	if d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected no-auth dial error")
		}
	}

	badPwd := &proxy.Auth{User: "foo", Password: "not right"}
	if d, err := proxy.SOCKS5("tcp", addr, badPwd, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad password dial error")
		}
	}

	badUsr := &proxy.Auth{User: "not right", Password: "bar"}
	if d, err := proxy.SOCKS5("tcp", addr, badUsr, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad username dial error")
		}
	}

	socksDialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
