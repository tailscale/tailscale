// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestListen(t *testing.T) {
	epCh := make(chan string, 16)
	epFunc := func(endpoints []string) {
		for _, ep := range endpoints {
			epCh <- ep
		}
	}

	// TODO(crawshaw): break test dependency on the network
	// using "gortc.io/stun" (like stunner_test.go).
	stunServers := DefaultSTUN

	port := pickPort(t)
	conn, err := Listen(Options{
		Port:          port,
		STUN:          stunServers,
		EndpointsFunc: epFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		var pkt [1 << 16]byte
		for {
			_, _, _, err := conn.ReceiveIPv4(pkt[:])
			if err != nil {
				return
			}
		}
	}()

	timeout := time.After(10 * time.Second)
	var endpoints []string
	suffix := fmt.Sprintf(":%d", port)
collectEndpoints:
	for {
		select {
		case ep := <-epCh:
			endpoints = append(endpoints, ep)
			if strings.HasSuffix(ep, suffix) {
				break collectEndpoints
			}
		case <-timeout:
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}
