// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

type dummyNetConn struct {
	net.Conn
}

func (dummyNetConn) SetReadDeadline(time.Time) error { return nil }

func TestClientRecv(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  any
	}{
		{
			name: "ping",
			input: []byte{
				byte(FramePing), 0, 0, 0, 8,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			want: PingMessage{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name: "pong",
			input: []byte{
				byte(FramePong), 0, 0, 0, 8,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			want: PongMessage{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name: "health_bad",
			input: []byte{
				byte(FrameHealth), 0, 0, 0, 3,
				byte('B'), byte('A'), byte('D'),
			},
			want: HealthMessage{Problem: "BAD"},
		},
		{
			name: "health_ok",
			input: []byte{
				byte(FrameHealth), 0, 0, 0, 0,
			},
			want: HealthMessage{},
		},
		{
			name: "server_restarting",
			input: []byte{
				byte(FrameRestarting), 0, 0, 0, 8,
				0, 0, 0, 1,
				0, 0, 0, 2,
			},
			want: ServerRestartingMessage{
				ReconnectIn: 1 * time.Millisecond,
				TryFor:      2 * time.Millisecond,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				nc:    dummyNetConn{},
				br:    bufio.NewReader(bytes.NewReader(tt.input)),
				logf:  t.Logf,
				clock: &tstest.Clock{},
			}
			got, err := c.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestClientSendPing(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{
		bw: bufio.NewWriter(&buf),
	}
	if err := c.SendPing([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		byte(FramePing), 0, 0, 0, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("unexpected output\nwrote: % 02x\n want: % 02x", buf.Bytes(), want)
	}
}

func TestClientSendPong(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{
		bw: bufio.NewWriter(&buf),
	}
	if err := c.SendPong([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		byte(FramePong), 0, 0, 0, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("unexpected output\nwrote: % 02x\n want: % 02x", buf.Bytes(), want)
	}
}

func BenchmarkWriteUint32(b *testing.B) {
	w := bufio.NewWriter(io.Discard)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		writeUint32(w, 0x0ba3a)
	}
}

type nopRead struct{}

func (r nopRead) Read(p []byte) (int, error) {
	return len(p), nil
}

var sinkU32 uint32

func BenchmarkReadUint32(b *testing.B) {
	r := bufio.NewReader(nopRead{})
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sinkU32, err = readUint32(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type countWriter struct {
	mu     sync.Mutex
	writes int
	bytes  int64
}

func (w *countWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	w.bytes += int64(len(p))
	return len(p), nil
}

func (w *countWriter) Stats() (writes int, bytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes, w.bytes
}

func (w *countWriter) ResetStats() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes, w.bytes = 0, 0
}

func TestClientSendRateLimiting(t *testing.T) {
	cw := new(countWriter)
	c := &Client{
		bw:    bufio.NewWriter(cw),
		clock: &tstest.Clock{},
	}
	c.setSendRateLimiter(ServerInfoMessage{})

	pkt := make([]byte, 1000)
	if err := c.send(key.NodePublic{}, pkt); err != nil {
		t.Fatal(err)
	}
	writes1, bytes1 := cw.Stats()
	if writes1 != 1 {
		t.Errorf("writes = %v, want 1", writes1)
	}

	// Flood should all succeed.
	cw.ResetStats()
	for range 1000 {
		if err := c.send(key.NodePublic{}, pkt); err != nil {
			t.Fatal(err)
		}
	}
	writes1K, bytes1K := cw.Stats()
	if writes1K != 1000 {
		t.Logf("writes = %v; want 1000", writes1K)
	}
	if got, want := bytes1K, bytes1*1000; got != want {
		t.Logf("bytes = %v; want %v", got, want)
	}

	// Set a rate limiter
	cw.ResetStats()
	c.setSendRateLimiter(ServerInfoMessage{
		TokenBucketBytesPerSecond: 1,
		TokenBucketBytesBurst:     int(bytes1 * 2),
	})
	for range 1000 {
		if err := c.send(key.NodePublic{}, pkt); err != nil {
			t.Fatal(err)
		}
	}
	writesLimited, bytesLimited := cw.Stats()
	if writesLimited == 0 || writesLimited == writes1K {
		t.Errorf("limited conn's write count = %v; want non-zero, less than 1k", writesLimited)
	}
	if bytesLimited < bytes1*2 || bytesLimited >= bytes1K {
		t.Errorf("limited conn's bytes count = %v; want >=%v, <%v", bytesLimited, bytes1K*2, bytes1K)
	}
}
