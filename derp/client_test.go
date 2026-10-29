// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go4.org/mem"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
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

// fwdTestConn is a derp.Conn for ForwardPacket tests. Writes go to w,
// and Close is counted.
type fwdTestConn struct {
	dummyNetConn
	w      io.Writer
	closes atomic.Int32
}

func (c *fwdTestConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *fwdTestConn) Close() error                     { c.closes.Add(1); return nil }
func (c *fwdTestConn) SetWriteDeadline(time.Time) error { return nil }

// newForwardTestClient returns a Client whose writes go to w through
// a bufio.Writer of bufSize bytes, along with its connection.
func newForwardTestClient(w io.Writer, bufSize int) (*Client, *fwdTestConn) {
	nc := &fwdTestConn{w: w}
	c := &Client{
		nc:    nc,
		bw:    bufio.NewWriterSize(nc, bufSize),
		clock: tstime.StdClock{},
		logf:  logger.Discard,
	}
	return c, nc
}

// forwardFrame is the wire encoding of a forward packet frame.
func forwardFrame(src, dst key.NodePublic, payload []byte) []byte {
	var b []byte
	b = append(b, byte(FrameForwardPacket))
	b = binary.BigEndian.AppendUint32(b, uint32(KeyLen*2+len(payload)))
	b = src.AppendTo(b)
	b = dst.AppendTo(b)
	return append(b, payload...)
}

// TestClientForwardPacketDeferredFlush checks that a single
// ForwardPacket's frame reaches the connection intact without any
// further call: the deferred flush runs on its own. In the synctest
// bubble, synctest.Wait returns once the flush goroutine has exited.
func TestClientForwardPacketDeferredFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		c, nc := newForwardTestClient(&out, 16<<10)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		payload := []byte("hello")
		if err := c.ForwardPacket(src, dst, LoanBytes(payload)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if want := forwardFrame(src, dst, payload); !bytes.Equal(out.Bytes(), want) {
			t.Errorf("single frame\n got: % 02x\nwant: % 02x", out.Bytes(), want)
		}
		if nc.closes.Load() != 0 {
			t.Errorf("connection closed %d times", nc.closes.Load())
		}
	})
}

// TestClientForwardPacketBatching checks that frames forwarded by many
// goroutines while a flush is in progress share the next flush, and
// all arrive intact.
//
// It can't use synctest: the point is to have goroutines queue on the
// write mutex, and a goroutine blocked on a mutex isn't durably
// blocked, so a bubble would never settle. Instead the connection's
// Write is held open mid-flush, so the flush goroutine sits in it
// holding the lock while n goroutines each forward a frame. They
// report in just before calling ForwardPacket, and once all have, the
// held write is released: they then write their frames ahead of the
// next flush, which therefore carries many of them. The frames that
// don't fit in the buffer flush it as they go, so the floor is about
// n*frameLen/bufSize writes, not 1. A goroutine that reported in but
// hadn't reached the lock yet when the write was released just
// contends normally, costing at most a write each, which the bound
// below has ample slack for.
func TestClientForwardPacketBatching(t *testing.T) {
	src, dst := key.NewNode().Public(), key.NewNode().Public()
	const n = 1000
	held := forwardFrame(src, dst, []byte("held"))
	frameLen := len(forwardFrame(src, dst, make([]byte, 4)))
	wantLen := len(held) + n*frameLen

	var mu sync.Mutex
	var out bytes.Buffer
	cw := new(countWriter)
	// When holdNextWrite is set, the next write to the connection
	// signals writeHeld and then blocks until releaseWrite is closed.
	// allWritten is closed once wantLen bytes have been written.
	var holdNextWrite atomic.Bool
	writeHeld := make(chan struct{})
	releaseWrite := make(chan struct{})
	allWritten := make(chan struct{})
	var allWrittenOnce sync.Once
	w := writerFunc(func(p []byte) (int, error) {
		if holdNextWrite.CompareAndSwap(true, false) {
			close(writeHeld)
			<-releaseWrite
		}
		mu.Lock()
		defer mu.Unlock()
		out.Write(p)
		if out.Len() >= wantLen {
			allWrittenOnce.Do(func() { close(allWritten) })
		}
		return cw.Write(p)
	})
	c, nc := newForwardTestClient(w, 16<<10)

	holdNextWrite.Store(true)
	if err := c.ForwardPacket(src, dst, LoanBytes([]byte("held"))); err != nil {
		t.Fatal(err)
	}
	<-writeHeld

	var reached, done sync.WaitGroup
	reached.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			p := binary.BigEndian.AppendUint32(nil, uint32(i))
			reached.Done()
			if err := c.ForwardPacket(src, dst, LoanBytes(p)); err != nil {
				t.Error(err)
			}
		}()
	}
	reached.Wait()
	close(releaseWrite)
	done.Wait()

	select {
	case <-allWritten:
	case <-time.After(10 * time.Second):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("timed out with %d of %d bytes written", out.Len(), wantLen)
	}
	mu.Lock()
	got := bytes.Clone(out.Bytes())
	mu.Unlock()
	if len(got) != wantLen {
		t.Fatalf("got %d bytes; want %d", len(got), wantLen)
	}

	br := bufio.NewReader(bytes.NewReader(got))
	readFrame := func() (fl uint32, body []byte) {
		t.Helper()
		ft, fl, err := ReadFrameHeader(br)
		if err != nil {
			t.Fatal(err)
		}
		if ft != FrameForwardPacket {
			t.Fatalf("frame type %d; want %d", ft, FrameForwardPacket)
		}
		body = make([]byte, fl)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body[:KeyLen], src.AppendTo(nil)) || !bytes.Equal(body[KeyLen:2*KeyLen], dst.AppendTo(nil)) {
			t.Fatal("wrong keys in frame")
		}
		return fl, body
	}
	if _, body := readFrame(); string(body[2*KeyLen:]) != "held" {
		t.Fatalf("first frame payload %q; want %q", body[2*KeyLen:], "held")
	}
	seen := make([]bool, n)
	for range n {
		fl, body := readFrame()
		if fl != uint32(KeyLen*2+4) {
			t.Fatalf("frame len %d; want %d", fl, KeyLen*2+4)
		}
		i := binary.BigEndian.Uint32(body[2*KeyLen:])
		if seen[i] {
			t.Fatalf("frame %d seen twice", i)
		}
		seen[i] = true
	}
	writes, _ := cw.Stats()
	t.Logf("%d frames in %d writes", n+1, writes)
	if writes > n/10 {
		t.Errorf("%d writes for %d frames; want batching", writes, n+1)
	}
	if nc.closes.Load() != 0 {
		t.Errorf("connection closed %d times", nc.closes.Load())
	}
}

// TestClientForwardPacketFillsBuffer checks the path where a frame
// doesn't fit in the remaining buffer space: what's buffered is
// flushed first, and then frames bigger than the whole buffer still
// get through whole.
func TestClientForwardPacketFillsBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var out bytes.Buffer
		const bufSize = 256
		c, _ := newForwardTestClient(&out, bufSize)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		var want []byte
		for _, size := range []int{100, 100, 100, bufSize * 3, 1} {
			p := bytes.Repeat([]byte{byte(size)}, size)
			if err := c.ForwardPacket(src, dst, LoanBytes(p)); err != nil {
				t.Fatal(err)
			}
			want = append(want, forwardFrame(src, dst, p)...)
		}
		synctest.Wait()
		if !bytes.Equal(out.Bytes(), want) {
			t.Errorf("output mismatch:\n got %d bytes\nwant %d bytes", out.Len(), len(want))
		}
	})
}

// TestClientForwardPacketFlushError checks that an error from the
// deferred flush closes the connection and is returned by the next
// ForwardPacket call, so a derphttp.Client owner reconnects.
func TestClientForwardPacketFlushError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		wantErr := errors.New("boom")
		w := writerFunc(func(p []byte) (int, error) { return 0, wantErr })
		c, nc := newForwardTestClient(w, 16<<10)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		if err := c.ForwardPacket(src, dst, LoanBytes([]byte("x"))); err != nil {
			t.Fatalf("first call: %v", err) // buffered; the flush hasn't run yet
		}
		synctest.Wait() // the deferred flush has failed by now
		if got := nc.closes.Load(); got != 1 {
			t.Fatalf("connection closed %d times; want 1", got)
		}
		err := c.ForwardPacket(src, dst, LoanBytes([]byte("y")))
		if !errors.Is(err, wantErr) {
			t.Fatalf("second call err = %v; want %v", err, wantErr)
		}
		// And it stays that way.
		if err := c.ForwardPacket(src, dst, LoanBytes([]byte("z"))); !errors.Is(err, wantErr) {
			t.Fatalf("third call err = %v; want %v", err, wantErr)
		}
	})
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
