// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsp

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// errSessionClosed is returned by [MapSession.Next] and
// [MapSession.NextInto] when called after [MapSession.Close].
var errSessionClosed = errors.New("tsp: map session closed")

// DefaultMaxMessageSize is the default cap, in bytes, on the size of a
// single compressed map response frame. See [MapOpts.MaxMessageSize].
const DefaultMaxMessageSize = 4 << 20

// zstdDecoderPool is a pool of *zstd.Decoder reused across MapSessions to
// amortize the cost of setting up zstd state. Decoders are returned via
// [MapSession.Close]; entries are reclaimed by the runtime under memory
// pressure via sync.Pool semantics.
var zstdDecoderPool sync.Pool // of *zstd.Decoder

// MapOpts contains options for sending a map request.
type MapOpts struct {
	// NodeKey is the node's private key. Required.
	NodeKey key.NodePrivate

	// Hostinfo is the host information to send. Optional;
	// if nil, a minimal default is used.
	Hostinfo *tailcfg.Hostinfo

	// Stream is whether to receive multiple MapResponses over
	// the same HTTP connection.
	Stream bool

	// OmitPeers is whether the client is okay with the Peers list
	// being omitted in the response.
	OmitPeers bool

	// MaxMessageSize is the maximum size in bytes of any single
	// compressed map response frame on the wire. If zero,
	// [DefaultMaxMessageSize] is used.
	MaxMessageSize int64
}

// framedReader is an io.Reader that consumes a stream of length-prefixed
// frames (each a little-endian uint32 length followed by that many bytes)
// from r and yields only the frame payloads back-to-back.
//
// This lets us feed the concatenated zstd frames from our wire protocol
// into a single streaming zstd decoder. Zstd's file format permits
// concatenation (RFC 8478 §2), and klauspost's decoder handles it
// transparently.
//
// If onNewFrame is non-nil, it is called after each new 4-byte length
// header is successfully read. Used to reset the per-message decoded-size
// budget downstream.
type framedReader struct {
	r          io.Reader
	maxSize    int64 // per-frame compressed-size cap
	remain     int   // bytes remaining in the current frame
	onNewFrame func()
}

func (f *framedReader) Read(p []byte) (int, error) {
	if f.remain == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
			return 0, err
		}
		sz := int64(binary.LittleEndian.Uint32(hdr[:]))
		if sz == 0 {
			return 0, fmt.Errorf("map response: zero-length frame")
		}
		if sz > f.maxSize {
			return 0, fmt.Errorf("map response frame size %d exceeds max %d", sz, f.maxSize)
		}
		f.remain = int(sz)
		if f.onNewFrame != nil {
			f.onNewFrame()
		}
	}
	if len(p) > f.remain {
		p = p[:f.remain]
	}
	n, err := f.r.Read(p)
	f.remain -= n
	return n, err
}

// boundedReader is an io.Reader that yields at most remain bytes from r
// before returning an error. Call reset to raise the budget back to max,
// typically at a new message boundary.
//
// Used to cap the decoded size of a single map response so a malicious
// server can't send a small zstd frame that explodes into gigabytes of
// junk for the json.Decoder to consume.
type boundedReader struct {
	r      io.Reader
	max    int64
	remain int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.remain <= 0 {
		return 0, fmt.Errorf("map response decoded size exceeds max %d", b.max)
	}
	if int64(len(p)) > b.remain {
		p = p[:b.remain]
	}
	n, err := b.r.Read(p)
	b.remain -= int64(n)
	return n, err
}

func (b *boundedReader) reset() { b.remain = b.max }

// MapSession wraps an in-progress map response stream. Call Next to read
// each MapResponse. Call Close when done.
type MapSession struct {
	res       *http.Response
	stream    bool
	noiseDoer func(*http.Request) (*http.Response, error)

	// inNext detects concurrent NextInto callers. It CAS-flips
	// false→true on entry and back to false on exit; a failed CAS
	// panics, akin to how the Go runtime detects concurrent map
	// access. It does not serialize Close vs. NextInto; that's
	// nextMu's job.
	inNext atomic.Bool

	// nextMu is held while [MapSession.NextInto] is running jdec.Decode,
	// so that Close can wait for an in-flight Decode to unwind before it
	// touches zdec (Reset, pool-Put) and avoids racing with the running
	// Read chain that Decode drives.
	nextMu sync.Mutex
	read   int           // guarded by nextMu
	closed bool          // guarded by nextMu
	zdec   *zstd.Decoder // reads from a framedReader wrapping res.Body
	jdec   *json.Decoder // reads decompressed JSON from zdec

	closeOnce sync.Once
	closeErr  error
}

// NoiseRoundTrip sends an HTTP request over the Noise channel used by this map session.
func (s *MapSession) NoiseRoundTrip(req *http.Request) (*http.Response, error) {
	return s.noiseDoer(req)
}

// Next reads and returns the next MapResponse from the stream.
// For non-streaming sessions, the first call returns the single response
// and subsequent calls return io.EOF.
// For streaming sessions, Next blocks until the next response arrives
// or the server closes the connection.
//
// Each call allocates a fresh MapResponse. Callers that want to amortize
// the allocation across calls can use [MapSession.NextInto].
//
// Next and NextInto are not safe to call concurrently from multiple
// goroutines on the same [MapSession]; a concurrent call panics, akin
// to the Go runtime's concurrent map access detection. [MapSession.Close]
// may be called concurrently to abort an in-flight Next.
func (s *MapSession) Next() (*tailcfg.MapResponse, error) {
	var resp tailcfg.MapResponse
	if err := s.NextInto(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// NextInto is like [MapSession.Next] but decodes the next MapResponse into
// the caller-supplied *resp rather than allocating a new one. The pointer's
// pointee is zeroed before decoding so fields from a prior response do not
// persist.
//
// For non-streaming sessions, the first call decodes the single response
// and subsequent calls return io.EOF.
// For streaming sessions, NextInto blocks until the next response arrives
// or the server closes the connection.
//
// See [MapSession.Next] for concurrency rules; those apply to NextInto too.
func (s *MapSession) NextInto(resp *tailcfg.MapResponse) error {
	if !s.inNext.CompareAndSwap(false, true) {
		panic("tsp: invalid concurrent call to MapSession.Next/NextInto")
	}
	defer s.inNext.Store(false)

	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	if s.closed {
		return errSessionClosed
	}
	if !s.stream && s.read > 0 {
		return io.EOF
	}
	*resp = tailcfg.MapResponse{}
	if err := s.jdec.Decode(resp); err != nil {
		return err
	}
	s.read++
	return nil
}

// Close returns the session's zstd decoder to the pool and closes the
// underlying HTTP response body. It is safe to call Close multiple times
// and from multiple goroutines, including while a [MapSession.Next] or
// [MapSession.NextInto] call is in flight on another goroutine (which
// will return an error once the body close propagates).
func (s *MapSession) Close() error {
	// Callers are likely to race a deferred Close with a time.AfterFunc
	// timeout (or similar) Close that aborts a hung Next. Without the
	// Once, both Closes would Put the same *zstd.Decoder into the pool,
	// corrupting it, and the Reset/Put in one would race with the
	// zdec.Read that the hung Next is driving.
	//
	// Ordering inside the Once: close the body first to unblock any
	// in-flight NextInto (its Read chain ends at res.Body and will
	// return an error once it's closed). That lets NextInto unwind and
	// release nextMu. Only then do we take nextMu ourselves and touch
	// zdec, which is safe because no goroutine is still reading from
	// it. Acquiring nextMu before closing the body would deadlock
	// against a hung NextInto.
	s.closeOnce.Do(func() {
		s.closeErr = s.res.Body.Close()
		s.nextMu.Lock()
		defer s.nextMu.Unlock()
		s.closed = true
		s.zdec.Reset(nil)
		zstdDecoderPool.Put(s.zdec)
	})
	return s.closeErr
}

// SendMapUpdateOpts contains options for [Client.SendMapUpdate].
type SendMapUpdateOpts struct {
	// NodeKey is the node's private key. Required.
	NodeKey key.NodePrivate

	// DiscoKey, if non-zero, is the node's disco public key.
	// Peers use it to verify disco pings from this node, which is
	// what enables direct (non-DERP) paths.
	DiscoKey key.DiscoPublic

	// Hostinfo is the host information to send. Optional;
	// if nil, a minimal default is used.
	Hostinfo *tailcfg.Hostinfo
}

// SendMapUpdate sends a one-shot, non-streaming MapRequest to push small
// updates (such as the node's endpoints, hostinfo, or disco public key) to the
// coordination server without starting or disturbing a streaming map session.
func (c *Client) SendMapUpdate(ctx context.Context, opts SendMapUpdateOpts) error {
	if opts.NodeKey.IsZero() {
		return fmt.Errorf("NodeKey is required")
	}

	hi := opts.Hostinfo
	if hi == nil {
		hi = defaultHostinfo()
	}

	mapReq := tailcfg.MapRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  opts.NodeKey.Public(),
		DiscoKey: opts.DiscoKey,
		Hostinfo: hi,
		Compress: "zstd",

		// A lite update that lets the server persist our state without breaking
		// any existing streaming map session. See the [tailcfg.MapResponse]
		// OmitPeers docs.
		OmitPeers: true,
		Stream:    false,
		ReadOnly:  false,
	}

	body, err := json.Marshal(mapReq)
	if err != nil {
		return fmt.Errorf("encoding map request: %w", err)
	}

	nc, err := c.noiseClient(ctx)
	if err != nil {
		return fmt.Errorf("establishing noise connection: %w", err)
	}

	url := c.serverURL + "/machine/map"
	url = strings.Replace(url, "http:", "https:", 1)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating map request: %w", err)
	}
	ts2021.AddLBHeader(req, opts.NodeKey.Public())

	res, err := nc.Do(req)
	if err != nil {
		return fmt.Errorf("map request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("map request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	io.Copy(io.Discard, res.Body)
	return nil
}

// Map sends a map request to the coordination server and returns a MapSession
// for reading the framed, zstd-compressed response(s).
func (c *Client) Map(ctx context.Context, opts MapOpts) (*MapSession, error) {
	if opts.NodeKey.IsZero() {
		return nil, fmt.Errorf("NodeKey is required")
	}

	hi := opts.Hostinfo
	if hi == nil {
		hi = defaultHostinfo()
	}

	mapReq := tailcfg.MapRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   opts.NodeKey.Public(),
		Hostinfo:  hi,
		Stream:    opts.Stream,
		Compress:  "zstd",
		OmitPeers: opts.OmitPeers,
		// Streaming requires the server to track us as "connected",
		// which in turn requires ReadOnly=false. Non-streaming polls
		// stay ReadOnly to minimize side effects.
		ReadOnly: !opts.Stream,
	}

	body, err := json.Marshal(mapReq)
	if err != nil {
		return nil, fmt.Errorf("encoding map request: %w", err)
	}

	nc, err := c.noiseClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("establishing noise connection: %w", err)
	}

	url := c.serverURL + "/machine/map"
	url = strings.Replace(url, "http:", "https:", 1)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating map request: %w", err)
	}
	ts2021.AddLBHeader(req, opts.NodeKey.Public())

	res, err := nc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("map request: %w", err)
	}

	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("map request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}

	maxMessageSize := cmp.Or(opts.MaxMessageSize, DefaultMaxMessageSize)
	bounded := &boundedReader{max: maxMessageSize, remain: maxMessageSize}
	fr := &framedReader{
		r:          res.Body,
		maxSize:    maxMessageSize,
		onNewFrame: bounded.reset,
	}

	zdec, _ := zstdDecoderPool.Get().(*zstd.Decoder)
	if zdec != nil {
		if err := zdec.Reset(fr); err != nil {
			// Reset can fail if the previous stream is in a bad state; drop
			// the decoder and create a fresh one.
			zdec = nil
		}
	}
	if zdec == nil {
		zdec, err = zstd.NewReader(fr, zstd.WithDecoderConcurrency(1))
		if err != nil {
			res.Body.Close()
			return nil, fmt.Errorf("creating zstd decoder: %w", err)
		}
	}
	bounded.r = zdec

	return &MapSession{
		res:       res,
		stream:    opts.Stream,
		noiseDoer: nc.Do,
		zdec:      zdec,
		jdec:      json.NewDecoder(bounded),
	}, nil
}
