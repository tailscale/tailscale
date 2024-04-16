// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tcpinfo

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"testing"
)

func TestRTT(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin":
	default:
		t.Skipf("not currently supported on %s", runtime.GOOS)
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })

			// Copy from the client to nowhere
			go io.Copy(io.Discard, c)
		}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Write a bunch of data to the conn to force TCP session establishment
	// and a few packets.
	junkData := bytes.Repeat([]byte("hello world\n"), 1024*1024)
	for i := range 10 {
		if _, err := conn.Write(junkData); err != nil {
			t.Fatalf("error writing junk data [%d]: %v", i, err)
		}
	}

	// Get the RTT now
	rtt, err := RTT(conn)
	if err != nil {
		t.Fatalf("error getting RTT: %v", err)
	}
	if rtt == 0 {
		t.Errorf("expected RTT > 0")
	}

	t.Logf("TCP rtt: %v", rtt)
}
