// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package driveimpl

import (
	"log"
	"net"
	"testing"
)

func TestConnListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatalf("failed to Listen: %s", err)
	}

	cl := newConnListener()
	// Test that we can accept a connection
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to Dial: %s", err)
	}
	defer cc.Close()

	sc, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to Accept: %s", err)
	}

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.10.10.10"), Port: 1234}
	go func() {
		err := cl.HandleConn(sc, remoteAddr)
		if err != nil {
			log.Printf("failed to HandleConn: %s", err)
		}
	}()

	clc, err := cl.Accept()
	if err != nil {
		t.Fatalf("failed to Accept: %s", err)
	}
	defer clc.Close()

	if clc.RemoteAddr().String() != remoteAddr.String() {
		t.Fatalf("ConnListener accepted the wrong connection, got %q, want %q", clc.RemoteAddr(), remoteAddr)
	}

	err = cl.Close()
	if err != nil {
		t.Fatalf("failed to Close: %s", err)
	}

	err = cl.Close()
	if err == nil {
		t.Fatal("should have failed on second Close")
	}

	err = cl.HandleConn(sc, remoteAddr)
	if err == nil {
		t.Fatal("should have failed on HandleConn after Close")
	}

	_, err = cl.Accept()
	if err == nil {
		t.Fatal("should have failed on Accept after Close")
	}
}
