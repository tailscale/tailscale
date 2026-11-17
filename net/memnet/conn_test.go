// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package memnet

import (
	"errors"
	"io"
	"net"
	"testing"

	"golang.org/x/net/nettest"
)

func TestConn(t *testing.T) {
	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		c1, c2 = NewConn("test", bufferSize)
		return c1, c2, func() {
			c1.Close()
			c2.Close()
		}, nil
	})
}

func TestConnCloseWriteAndCloseRead(t *testing.T) {
	a, b := NewConn("test", bufferSize)
	// Half-close is not part of the Conn interface, matching net.Conn.
	ac := a.(interface{ CloseWrite() error })
	bc := b.(interface{ CloseRead() error })

	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := ac.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Buffered data survives the half-close; the next read is EOF.
	buf := make([]byte, 8)
	if n, err := b.Read(buf); n != 5 || err != nil {
		t.Fatalf("Read = %d, %v; want 5, nil", n, err)
	}
	if _, err := b.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after CloseWrite = %v; want io.EOF", err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("Write after CloseWrite succeeded")
	}

	if err := bc.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after CloseRead = %v; want io.EOF", err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("Write after peer CloseRead succeeded")
	}
}
