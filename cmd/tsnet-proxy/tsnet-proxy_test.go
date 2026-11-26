// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyTCPClosesUpstream(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	upstreamClosed := make(chan struct{})
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("hello"))
		// Never close from this side: the proxy must close us once the
		// client goes away.
		io.Copy(io.Discard, c)
		close(upstreamClosed)
	}()

	client, proxied := net.Pipe()
	go proxyTCP(proxied, backend.Addr().String())

	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
	client.Close()

	select {
	case <-upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection not closed after client disconnect")
	}
}
