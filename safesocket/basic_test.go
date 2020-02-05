// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"fmt"
	"testing"
)

func TestBasics(t *testing.T) {
	fmt.Printf("listening2...\n")
	l, port, err := Listen("COOKIE", "Tailscale", "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("listened.\n")

	go func() {
		fmt.Printf("accepting...\n")
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("accepted.\n")
		l.Close()
		s.Write([]byte("hello"))
		fmt.Printf("server wrote.\n")

		b := make([]byte, 1024)
		n, err := s.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("server read %d bytes.\n", n)
		if string(b[:n]) != "world" {
			t.Fatalf("got %#v, expected %#v\n", string(b[:n]), "world")
		}
		s.Close()
	}()

	fmt.Printf("connecting...\n")
	c, err := Connect("COOKIE", "Tailscale", "test", port)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("connected.\n")
	c.Write([]byte("world"))
	fmt.Printf("client wrote.\n")

	b := make([]byte, 1024)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("client read %d bytes.\n", n)
	if string(b[:n]) != "hello" {
		t.Fatalf("got %#v, expected %#v\n", string(b[:n]), "hello")
	}

	c.Close()
}
