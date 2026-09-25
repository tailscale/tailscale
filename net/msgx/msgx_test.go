// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package msgx

import (
	"net"
	"testing"
	"time"
)

func TestAvailable(t *testing.T) {
	if !Available() {
		t.Skipf("msgx unavailable: %v", UnavailableReason())
	}
}

// TestRoundTrip sends a burst of datagrams over loopback with sendmsg_x and
// reads them back with recvmsg_x in batches, checking counts, contents, and
// source addresses. It exercises the same path as the self-test but with more
// datagrams than fit one call.
func TestRoundTrip(t *testing.T) {
	if !Available() {
		t.Skipf("msgx unavailable: %v", UnavailableReason())
	}
	recvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer recvConn.Close()
	sendConn, err := net.DialUDP("udp4", nil, recvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sendConn.Close()
	sendRC, _ := sendConn.SyscallConn()
	recvRC, _ := recvConn.SyscallConn()

	const count = 300 // more than MaxBatch and more than the kernel's 256 cap
	payloads := make([][]byte, count)
	for i := range payloads {
		payloads[i] = []byte{byte(i), byte(i >> 8), 'x'}
	}
	for rem := payloads; len(rem) > 0; {
		n, err := Send(sendRC, rem)
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
		if n == 0 {
			t.Fatal("Send accepted nothing")
		}
		rem = rem[n:]
	}

	recvConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	from := sendConn.LocalAddr().(*net.UDPAddr).AddrPort()
	msgs := make([]Message, MaxBatch)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 16)
	}
	got := 0
	batches := 0
	for got < count {
		n, err := Recv(recvRC, msgs)
		if err != nil {
			t.Fatalf("Recv after %d datagrams: %v", got, err)
		}
		batches++
		for _, m := range msgs[:n] {
			want := payloads[got]
			if m.N != len(want) || string(m.Payload[:m.N]) != string(want) {
				t.Fatalf("datagram %d: got %q, want %q", got, m.Payload[:m.N], want)
			}
			if m.Addr != from {
				t.Fatalf("datagram %d: source %v, want %v", got, m.Addr, from)
			}
			got++
		}
	}
	if batches >= count {
		t.Errorf("no batching: %d datagrams took %d Recv calls", count, batches)
	}
	t.Logf("%d datagrams in %d Recv calls", count, batches)
}
