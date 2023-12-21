// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package connlistener

import (
	"net"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestConnListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	qt.Assert(t, err, qt.IsNil)

	connListener := New()
	// Test that we can accept a connection
	cc, err := net.Dial("tcp", listener.Addr().String())
	qt.Assert(t, err, qt.IsNil)
	defer cc.Close()

	sc, err := listener.Accept()
	qt.Assert(t, err, qt.IsNil)

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.10.10.10"), Port: 1234}
	err = connListener.HandleConn(sc, remoteAddr)
	qt.Assert(t, err, qt.IsNil)

	clc, err := connListener.Accept()
	qt.Assert(t, err, qt.IsNil)
	defer clc.Close()

	qt.Assert(t, clc.RemoteAddr().String(), qt.Equals, remoteAddr.String(), qt.Commentf("ConnListener should have accepted the right connection"))

	err = connListener.Close()
	qt.Assert(t, err, qt.IsNil)

	err = connListener.Close()
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("ConnListener should have returned an error on second close"))

	err = connListener.HandleConn(sc, remoteAddr)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("ConnListener should have returned an error on ConnAvailable after close"))

	_, err = connListener.Accept()
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("ConnListener should have returned an error on Accept after close"))
}
