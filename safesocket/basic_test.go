// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"fmt"
	"testing"
)

func TestBasics(t *testing.T) {
	l, port, err := Listen("test", 0)
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 2)

	go func() {
		s, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		l.Close()
		s.Write([]byte("hello"))

		b := make([]byte, 1024)
		n, err := s.Read(b)
		if err != nil {
			errs <- err
			return
		}
		fmt.Printf("server read %d bytes.\n", n)
		if string(b[:n]) != "world" {
			errs <- fmt.Errorf("got %#v, expected %#v\n", string(b[:n]), "world")
			return
		}
		s.Close()
		errs <- nil
	}()

	go func() {
		c, err := Connect("test", port)
		if err != nil {
			errs <- err
			return
		}
		c.Write([]byte("world"))
		b := make([]byte, 1024)
		n, err := c.Read(b)
		if err != nil {
			errs <- err
			return
		}
		if string(b[:n]) != "hello" {
			errs <- fmt.Errorf("got %#v, expected %#v\n", string(b[:n]), "hello")
		}
		c.Close()
		errs <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
