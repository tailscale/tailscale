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
	"runtime"
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
// Close is counted, and overlapping Write calls are reported, as some
// Conn implementations (net/wsconn) panic on them.
type fwdTestConn struct {
	dummyNetConn
	t       testing.TB
	w       io.Writer
	closes  atomic.Int32
	writing atomic.Bool
}

func (c *fwdTestConn) Write(p []byte) (int, error) {
	if !c.writing.CompareAndSwap(false, true) {
		c.t.Error("concurrent writes to the connection")
	}
	defer c.writing.Store(false)
	return c.w.Write(p)
}
func (c *fwdTestConn) Close() error                     { c.closes.Add(1); return nil }
func (c *fwdTestConn) SetWriteDeadline(time.Time) error { return nil }

// newForwardTestClient returns a Client whose connection writes go to
// w, along with the connection.
func newForwardTestClient(t testing.TB, w io.Writer) (*Client, *fwdTestConn) {
	nc := &fwdTestConn{t: t, w: w}
	c := &Client{
		nc:    nc,
		bw:    bufio.NewWriter(nc),
		clock: tstime.StdClock{},
		logf:  logger.Discard,
	}
	return c, nc
}

// forwardFrame is the wire encoding of a forward packet frame.
func forwardFrame(src, dst key.NodePublic, payload []byte) []byte {
	b := AppendFrameHeader(nil, FrameForwardPacket, uint32(KeyLen*2+len(payload)))
	b = src.AppendTo(b)
	b = dst.AppendTo(b)
	return append(b, payload...)
}

// gatedWriter is an io.Writer that records what's written and, while
// gated, blocks each Write until the test sends on gate, so the test
// controls exactly when each write completes. pending reports whether
// a Write is blocked on the gate. The gate is created in the synctest
// bubble that uses it, so blocking on it is durable.
type gatedWriter struct {
	mu      sync.Mutex
	out     bytes.Buffer
	writes  int
	gated   atomic.Bool
	pending atomic.Bool
	gate    chan struct{}
	err     error // returned by every write once set
}

func newGatedWriter() *gatedWriter {
	return &gatedWriter{gate: make(chan struct{})}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	if w.gated.Load() {
		w.pending.Store(true)
		<-w.gate
		w.pending.Store(false)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	w.writes++
	return w.out.Write(p)
}

// releaseAll lets gated writes complete one at a time until the
// bubble is quiescent with no write pending, and returns how many it
// released. Between releases it waits for the bubble to settle, so
// callers waiting for room have refilled the buffer before the next
// write is let through.
func (w *gatedWriter) releaseAll() (released int) {
	for {
		synctest.Wait()
		if !w.pending.Load() {
			return released
		}
		w.gate <- struct{}{}
		released++
	}
}

func (w *gatedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.out.Bytes())
}

func (w *gatedWriter) writeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

func (w *gatedWriter) setErr(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
}

// forwardBufCaps returns the capacities of c's two forward buffers.
func forwardBufCaps(c *Client) (buf, spare int) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return cap(c.fwdBuf), cap(c.fwdSpare)
}

// readForwardFrames decodes b as a sequence of forward packet frames
// from src to dst and returns their payloads.
func readForwardFrames(t *testing.T, b []byte, src, dst key.NodePublic) (payloads [][]byte) {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(b))
	for {
		if _, err := br.Peek(1); err == io.EOF {
			break
		}
		ft, fl, err := ReadFrameHeader(br)
		if err != nil {
			t.Fatal(err)
		}
		if ft != FrameForwardPacket {
			t.Fatalf("frame type %d; want %d", ft, FrameForwardPacket)
		}
		body := make([]byte, fl)
		if _, err := io.ReadFull(br, body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body[:KeyLen], src.AppendTo(nil)) || !bytes.Equal(body[KeyLen:2*KeyLen], dst.AppendTo(nil)) {
			t.Fatal("wrong keys in frame")
		}
		payloads = append(payloads, body[2*KeyLen:])
	}
	return payloads
}

// TestClientForwardPacketDeferredWrite checks that a lone forward's
// frame reaches the connection intact without any further call, and
// that the caller didn't write it itself: synctest.Wait is what lets
// the flusher goroutine run to completion.
func TestClientForwardPacketDeferredWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newGatedWriter()
		c, nc := newForwardTestClient(t, w)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		payload := []byte("hello")
		if err := c.ForwardPacket(src, dst, LoanBytes(payload)); err != nil {
			t.Fatal(err)
		}
		if n := w.writeCount(); n != 0 {
			t.Fatalf("%d writes before the flusher ran; want 0", n)
		}
		synctest.Wait()
		if got, want := w.bytes(), forwardFrame(src, dst, payload); !bytes.Equal(got, want) {
			t.Errorf("single frame\n got: % 02x\nwant: % 02x", got, want)
		}
		if w.writeCount() != 1 || nc.closes.Load() != 0 {
			t.Errorf("writes = %d, closes = %d; want 1, 0", w.writeCount(), nc.closes.Load())
		}
	})
}

// TestClientForwardPacketBatching checks that frames forwarded by many
// goroutines while a write is in progress share the following writes,
// and all arrive intact. Writes are gated and let through one at a
// time, with the bubble settled before each, so every write after the
// first carries a full buffer: the number of writes is a function of
// the bytes forwarded and the buffer size, not of scheduling.
func TestClientForwardPacketBatching(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newGatedWriter()
		w.gated.Store(true)
		c, _ := newForwardTestClient(t, w)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		if err := c.ForwardPacket(src, dst, LoanBytes([]byte("held"))); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the flusher is in the gated write of that frame alone
		if !w.pending.Load() {
			t.Fatal("first forward is not in a write")
		}
		const n = 1000
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				p := binary.BigEndian.AppendUint32(nil, uint32(i))
				if err := c.ForwardPacket(src, dst, LoanBytes(p)); err != nil {
					t.Error(err)
				}
			})
		}
		// Every goroutine has now either buffered its frame or is
		// waiting for room, and nothing has reached the connection.
		synctest.Wait()
		if got := w.bytes(); len(got) != 0 {
			t.Fatalf("%d bytes written before any write was released; want 0", len(got))
		}
		w.releaseAll()
		wg.Wait()

		payloads := readForwardFrames(t, w.bytes(), src, dst)
		if len(payloads) != n+1 {
			t.Fatalf("got %d frames; want %d", len(payloads), n+1)
		}
		if string(payloads[0]) != "held" {
			t.Fatalf("first frame payload %q; want %q", payloads[0], "held")
		}
		seen := make([]bool, n)
		for _, p := range payloads[1:] {
			if len(p) != 4 {
				t.Fatalf("payload len %d; want 4", len(p))
			}
			i := binary.BigEndian.Uint32(p)
			if seen[i] {
				t.Fatalf("frame %d seen twice", i)
			}
			seen[i] = true
		}
		// The first write carried the held frame alone; the rest
		// each carried as many frames as fit in a buffer.
		frameLen := len(forwardFrame(src, dst, make([]byte, 4)))
		perBuf := forwardBufSize / frameLen
		if got, want := w.writeCount(), 1+(n+perBuf-1)/perBuf; got != want {
			t.Errorf("%d writes for %d frames; want %d", got, n+1, want)
		}
	})
}

// TestClientForwardPacketBufferFull checks backpressure: a caller that
// finds the buffer full while the other buffer is being written waits,
// rather than growing the buffer or dropping the frame, and proceeds
// once the write completes, with every frame delivered in order.
func TestClientForwardPacketBufferFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newGatedWriter()
		w.gated.Store(true)
		c, _ := newForwardTestClient(t, w)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		if err := c.ForwardPacket(src, dst, LoanBytes([]byte{0})); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the flusher is in the gated write

		// Enough frames to overflow the buffer several times over.
		payload := make([]byte, 1000)
		frameLen := len(forwardFrame(src, dst, payload))
		n := 5 * forwardBufSize / frameLen
		var done atomic.Bool
		go func() {
			for i := range n {
				payload[0] = byte(i)
				if err := c.ForwardPacket(src, dst, LoanBytes(payload)); err != nil {
					t.Error(err)
					return
				}
			}
			done.Store(true)
		}()
		synctest.Wait()
		if done.Load() {
			t.Fatal("caller didn't wait for room while the write was held")
		}
		if bufCap, _ := forwardBufCaps(c); bufCap != forwardBufSize {
			t.Errorf("buffer grew to cap %d; want %d", bufCap, forwardBufSize)
		}
		w.gated.Store(false)
		w.releaseAll() // the one write blocked on the gate
		if !done.Load() {
			t.Fatal("caller still waiting after the write was released")
		}
		payloads := readForwardFrames(t, w.bytes(), src, dst)
		if len(payloads) != n+1 {
			t.Fatalf("got %d frames; want %d", len(payloads), n+1)
		}
		for i, p := range payloads[1:] {
			if len(p) != len(payload) || p[0] != byte(i) {
				t.Fatalf("frame %d out of order or corrupt", i)
			}
		}
	})
}

// TestClientForwardPacketOversizedFrame checks that a frame bigger
// than a whole buffer still goes through whole and in order, and that
// the buffer it grew is not kept afterwards.
func TestClientForwardPacketOversizedFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newGatedWriter()
		c, _ := newForwardTestClient(t, w)
		src, dst := key.NewNode().Public(), key.NewNode().Public()

		var want []byte
		for _, size := range []int{100, 3 * forwardBufSize, 1, MaxPacketSize, 2} {
			p := bytes.Repeat([]byte{byte(size)}, size)
			if err := c.ForwardPacket(src, dst, LoanBytes(p)); err != nil {
				t.Fatal(err)
			}
			want = append(want, forwardFrame(src, dst, p)...)
		}
		synctest.Wait()
		if got := w.bytes(); !bytes.Equal(got, want) {
			t.Errorf("output mismatch: got %d bytes, want %d", len(got), len(want))
		}
		if bufCap, spareCap := forwardBufCaps(c); bufCap != forwardBufSize || spareCap != forwardBufSize {
			t.Errorf("buffer caps %d and %d after oversized frames; want %d", bufCap, spareCap, forwardBufSize)
		}
	})
}

// TestClientForwardPacketWriteError checks that a failed write closes
// the connection, wakes a caller waiting for room with the error, and
// returns it from every later call without starting another flusher,
// so a derphttp.Client owner reconnects.
func TestClientForwardPacketWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newGatedWriter()
		w.gated.Store(true)
		c, nc := newForwardTestClient(t, w)
		src, dst := key.NewNode().Public(), key.NewNode().Public()
		wantErr := errors.New("boom")

		// Hold the first write, fill the other buffer so a caller
		// waits, then make the held write fail.
		if err := c.ForwardPacket(src, dst, LoanBytes([]byte("x"))); err != nil {
			t.Fatal(err)
		}
		synctest.Wait() // the flusher is in the gated write
		payload := make([]byte, 1000)
		waiterErr := make(chan error, 1)
		go func() {
			for {
				if err := c.ForwardPacket(src, dst, LoanBytes(payload)); err != nil {
					waiterErr <- err
					return
				}
			}
		}()
		synctest.Wait() // the goroutine is waiting for room
		w.setErr(wantErr)
		w.gated.Store(false)
		w.releaseAll()

		if got := nc.closes.Load(); got != 1 {
			t.Fatalf("connection closed %d times; want 1", got)
		}
		select {
		case err := <-waiterErr:
			if !errors.Is(err, wantErr) {
				t.Fatalf("waiting caller got %v; want %v", err, wantErr)
			}
		default:
			t.Fatal("waiting caller was not woken by the failed write")
		}
		for i := range 2 {
			if err := c.ForwardPacket(src, dst, LoanBytes([]byte("y"))); !errors.Is(err, wantErr) {
				t.Fatalf("call %d after failure err = %v; want %v", i, err, wantErr)
			}
		}
		synctest.Wait()
		if got := nc.closes.Load(); got != 1 {
			t.Fatalf("connection closed %d times after later calls; want still 1", got)
		}
		if got := w.writeCount(); got != 0 {
			t.Fatalf("%d successful writes after the failure; want 0", got)
		}
	})
}

// TestClientForwardPacketSerializesConnWrites checks that the client's
// other senders can't write to the connection while a forward buffer
// is being written, since that write happens with wmu released and
// not every Conn tolerates overlapping writes.
//
// This can't run in a synctest bubble: the other sender blocks on a
// mutex, which isn't a durable block. The sleep only gives it time to
// reach the write before the forward's is released; a shorter one
// could let a regression slip past, but can't fail a correct client.
func TestClientForwardPacketSerializesConnWrites(t *testing.T) {
	w := newGatedWriter()
	w.gated.Store(true)
	c, _ := newForwardTestClient(t, w)
	src, dst := key.NewNode().Public(), key.NewNode().Public()

	fwdDone := make(chan error, 1)
	go func() { fwdDone <- c.ForwardPacket(src, dst, LoanBytes([]byte("fwd"))) }()
	for !w.pending.Load() {
		runtime.Gosched()
	}
	w.gated.Store(false)

	pingDone := make(chan error, 1)
	go func() { pingDone <- c.SendPing([8]byte{1}) }()
	time.Sleep(10 * time.Millisecond)
	if got := w.bytes(); len(got) != 0 {
		t.Fatalf("ping wrote %d bytes while the forward write was in progress", len(got))
	}
	w.gate <- struct{}{}
	for _, ch := range []chan error{fwdDone, pingDone} {
		if err := <-ch; err != nil {
			t.Fatal(err)
		}
	}
	want := append(forwardFrame(src, dst, []byte("fwd")), byte(FramePing), 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0)
	if got := w.bytes(); !bytes.Equal(got, want) {
		t.Errorf("wire order\n got: % 02x\nwant: % 02x", got, want)
	}
}
