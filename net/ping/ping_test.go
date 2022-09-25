// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ping

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"tailscale.com/tstest"
)

var (
	localhost    = &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	localhostUDP = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
)

func TestPinger(t *testing.T) {
	clock := &tstest.Clock{}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	p, closeP := mockPinger(t, clock)
	defer closeP()

	bodyData := []byte("data goes here")

	// Start a ping in the background
	r := make(chan time.Duration, 1)
	go func() {
		dur, err := p.Send(ctx, localhostUDP, bodyData)
		if err != nil {
			t.Errorf("p.Send: %v", err)
			r <- 0
		} else {
			r <- dur
		}
	}()

	p.waitOutstanding(t, ctx, 1)

	// Fake a response from ourself
	fakeResponse := mustMarshal(t, &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1234,
			Seq:  1,
			Data: bodyData,
		},
	})

	const fakeDuration = 100 * time.Millisecond
	p.handleResponse(fakeResponse, localhost, clock.Now().Add(fakeDuration))

	select {
	case dur := <-r:
		want := fakeDuration
		if dur != want {
			t.Errorf("wanted ping response time = %d; got %d", want, dur)
		}
	case <-ctx.Done():
		t.Fatal("did not get response by timeout")
	}
}

func TestPingerTimeout(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	clock := &tstest.Clock{}
	p, closeP := mockPinger(t, clock)
	defer closeP()

	// Send a ping in the background
	r := make(chan error, 1)
	go func() {
		_, err := p.Send(ctx, localhostUDP, []byte("data goes here"))
		r <- err
	}()

	// Wait until we're blocking
	p.waitOutstanding(t, ctx, 1)

	// Close everything down
	p.cleanupOutstanding()

	// Should have got an error from the ping
	err := <-r
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("wanted errors.Is(err, net.ErrClosed); got=%v", err)
	}
}

func TestPingerMismatch(t *testing.T) {
	clock := &tstest.Clock{}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second) // intentionally short
	defer cancel()

	p, closeP := mockPinger(t, clock)
	defer closeP()

	bodyData := []byte("data goes here")

	// Start a ping in the background
	r := make(chan time.Duration, 1)
	go func() {
		dur, err := p.Send(ctx, localhostUDP, bodyData)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("p.Send: %v", err)
			r <- 0
		} else {
			r <- dur
		}
	}()

	p.waitOutstanding(t, ctx, 1)

	// "Receive" a bunch of intentionally malformed packets that should not
	// result in the Send call above returning
	badPackets := []struct {
		name string
		pkt  *icmp.Message
	}{
		{
			name: "wrong type",
			pkt: &icmp.Message{
				Type: ipv4.ICMPTypeDestinationUnreachable,
				Code: 0,
				Body: &icmp.DstUnreach{},
			},
		},
		{
			name: "wrong id",
			pkt: &icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Code: 0,
				Body: &icmp.Echo{
					ID:   9999,
					Seq:  1,
					Data: bodyData,
				},
			},
		},
		{
			name: "wrong seq",
			pkt: &icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Code: 0,
				Body: &icmp.Echo{
					ID:   1234,
					Seq:  5,
					Data: bodyData,
				},
			},
		},
		{
			name: "bad body",
			pkt: &icmp.Message{
				Type: ipv4.ICMPTypeEchoReply,
				Code: 0,
				Body: &icmp.Echo{
					ID:  1234,
					Seq: 1,

					// Intentionally missing first byte
					Data: bodyData[1:],
				},
			},
		},
	}

	const fakeDuration = 100 * time.Millisecond
	tm := clock.Now().Add(fakeDuration)

	for _, tt := range badPackets {
		fakeResponse := mustMarshal(t, tt.pkt)
		p.handleResponse(fakeResponse, localhost, tm)
	}

	// Also "receive" a packet that does not unmarshal as an ICMP packet
	p.handleResponse([]byte("foo"), localhost, tm)

	select {
	case <-r:
		t.Fatal("wanted timeout")
	case <-ctx.Done():
		t.Logf("test correctly timed out")
	}
}

func mockPinger(t *testing.T, clock *tstest.Clock) (*Pinger, func()) {
	// In tests, we use UDP so that we can test without being root; this
	// doesn't matter because we mock out the ICMP reply below to be a real
	// ICMP echo reply packet.
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}

	p := &Pinger{
		c:       conn,
		Logf:    t.Logf,
		Verbose: true,
		timeNow: clock.Now,
		id:      1234,
		pings:   make(map[uint16]outstanding),
	}
	done := func() {
		if err := p.Close(); err != nil {
			t.Errorf("error on close: %v", err)
		}
	}
	return p, done
}

func mustMarshal(t *testing.T, m *icmp.Message) []byte {
	t.Helper()

	b, err := m.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p *Pinger) waitOutstanding(t *testing.T, ctx context.Context, count int) {
	// This is a bit janky, but... we busy-loop to wait for the Send call
	// to write to our map so we know that a response will be handled.
	var haveMapEntry bool
	for !haveMapEntry {
		time.Sleep(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Error("no entry in ping map before timeout")
			return
		default:
		}

		p.mu.Lock()
		haveMapEntry = len(p.pings) == count
		p.mu.Unlock()
	}
}
