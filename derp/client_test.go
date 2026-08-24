// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bufio"
	"bytes"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
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

// TestClientRecvPeerPresent tests that the client can parse peerPresent
// frames from servers of various eras: old servers that send fewer fields
// than the client knows about, and newer servers that send trailing fields
// the client doesn't know about, which it must ignore. This matters during
// rollouts of new DERP servers, when a region's meshed nodes and watchers
// run a mix of versions.
func TestClientRecvPeerPresent(t *testing.T) {
	keyb := bytes.Repeat([]byte{1}, KeyLen)
	k := key.NodePublicFromRaw32(mem.B(keyb))
	ipPort := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, // ::ffff:1.2.3.4
		0x12, 0x34, // port 4660
	}
	wantIPPort := netip.MustParseAddrPort("1.2.3.4:4660")

	frame := func(fields ...[]byte) []byte {
		b := []byte{byte(FramePeerPresent), 0, 0, 0, 0}
		for _, f := range fields {
			b = append(b, f...)
		}
		b[4] = byte(len(b) - FrameHeaderLen)
		return b
	}

	tests := []struct {
		name  string
		input []byte
		want  PeerPresentMessage
	}{
		{
			name:  "key_only_from_ancient_server",
			input: frame(keyb),
			want:  PeerPresentMessage{Key: k},
		},
		{
			name:  "ip_port_from_old_server",
			input: frame(keyb, ipPort),
			want:  PeerPresentMessage{Key: k, IPPort: wantIPPort},
		},
		{
			name:  "flags_from_current_server",
			input: frame(keyb, ipPort, []byte{PeerPresentIsRegular}),
			want:  PeerPresentMessage{Key: k, IPPort: wantIPPort, Flags: PeerPresentIsRegular},
		},
		{
			name:  "app_name_from_current_server",
			input: frame(keyb, ipPort, []byte{PeerPresentIsRegular}, []byte{3, 'a', 'b', 'c'}),
			want:  PeerPresentMessage{Key: k, IPPort: wantIPPort, Flags: PeerPresentIsRegular, AppName: "abc"},
		},
		{
			name: "extra_fields_from_newer_server",
			// A hypothetical newer server sending fields this client
			// doesn't know about. They must be ignored.
			input: frame(keyb, ipPort, []byte{PeerPresentIsRegular},
				[]byte{3, 'a', 'b', 'c'}, []byte{0xde, 0xad}),
			want: PeerPresentMessage{Key: k, IPPort: wantIPPort, Flags: PeerPresentIsRegular, AppName: "abc"},
		},
		{
			name: "truncated_app_name_ignored",
			// A buggy or malicious server sending an app name length
			// that exceeds the frame.
			input: frame(keyb, ipPort, []byte{PeerPresentIsRegular}, []byte{200, 'a', 'b', 'c'}),
			want:  PeerPresentMessage{Key: k, IPPort: wantIPPort, Flags: PeerPresentIsRegular},
		},
		{
			name:  "invalid_app_name_ignored",
			input: frame(keyb, ipPort, []byte{PeerPresentIsRegular}, []byte{3, 0x01, 0x02, 0x03}),
			want:  PeerPresentMessage{Key: k, IPPort: wantIPPort, Flags: PeerPresentIsRegular},
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
			m, err := c.Recv()
			if err != nil {
				t.Fatal(err)
			}
			got, ok := m.(PeerPresentMessage)
			if !ok {
				t.Fatalf("message type = %T; want PeerPresentMessage", m)
			}
			if got != tt.want {
				t.Errorf("got %+v; want %+v", got, tt.want)
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
