// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package connlistener

import (
	"net"
	"testing"
)

func TestConnListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}

	connListener := New()
	// Test that we can accept a connection
	cc, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	sc, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.10.10.10"), Port: 1234}
	err = connListener.HandleConn(sc, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}

	clc, err := connListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer clc.Close()

	if clc.RemoteAddr().String() != remoteAddr.String() {
		t.Errorf("ConnListener should have accepted the right connection, got %v, want %v", clc.RemoteAddr(), cc.LocalAddr())
	}

	err = connListener.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = connListener.Close()
	if err == nil {
		t.Error("ConnListener should have returned an error on second close")
	}

	err = connListener.HandleConn(sc, remoteAddr)
	if err == nil {
		t.Error("ConnListener should have returned an error on ConnAvailable after close")
	}

	_, err = connListener.Accept()
	if err == nil {
		t.Error("ConnListener should have returned an error on Accept after close")
	}
}
