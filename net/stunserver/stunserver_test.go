// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package stunserver

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/stun"
	"tailscale.com/util/must"
)

func TestSTUNServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx)
	must.Do(s.Listen("localhost:0"))
	var w sync.WaitGroup
	w.Add(1)
	var serveErr error
	go func() {
		defer w.Done()
		serveErr = s.Serve()
	}()

	c := must.Get(net.DialUDP("udp", nil, s.LocalAddr().(*net.UDPAddr)))
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	txid := stun.NewTxID()
	_, err := c.Write(stun.Request(txid))
	if err != nil {
		t.Fatalf("failed to write STUN request: %v", err)
	}
	var buf [64 << 10]byte
	n, err := c.Read(buf[:])
	if err != nil {
		t.Fatalf("failed to read STUN response: %v", err)
	}
	if !stun.Is(buf[:n]) {
		t.Fatalf("response is not STUN")
	}
	tid, _, err := stun.ParseResponse(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse STUN response: %v", err)
	}
	if tid != txid {
		t.Fatalf("STUN response has wrong transaction ID; got %d, want %d", tid, txid)
	}

	cancel()
	w.Wait()
	if serveErr != nil {
		t.Fatalf("failed to listen and serve: %v", serveErr)
	}
}

func BenchmarkServerSTUN(b *testing.B) {
	b.ReportAllocs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(ctx)
	s.Listen("localhost:0")
	go s.Serve()
	addr := s.LocalAddr().(*net.UDPAddr)

	var resBuf [1500]byte
	cc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		b.Fatal(err)
	}

	tx := stun.NewTxID()
	req := stun.Request(tx)
	for range b.N {
		if _, err := cc.WriteToUDP(req, addr); err != nil {
			b.Fatal(err)
		}
		_, _, err := cc.ReadFromUDP(resBuf[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
