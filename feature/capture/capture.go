// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package capture formats packet logging into a debug pcap stream.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/packet"
	"tailscale.com/util/set"
)

func init() {
	feature.Register("capture")
	localapi.Register("debug-capture", serveLocalAPIDebugCapture)
}

func serveLocalAPIDebugCapture(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()

	snapLen, _ := strconv.Atoi(r.URL.Query().Get("snaplen"))

	b := h.LocalBackend()
	s := b.GetOrSetCaptureSink(func() packet.CaptureSink { return newSink(snapLen) })

	unregister := s.RegisterOutput(w)

	select {
	case <-ctx.Done():
	case <-s.WaitCh():
	}
	unregister()

	b.ClearCaptureSink()
}

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

const flushPeriod = 100 * time.Millisecond

// defaultSnapLen is the pcap snapshot length used when a capture does not
// request one. It matches tcpdump's default; Tailscale packets are far smaller,
// so the default effectively never truncates.
const defaultSnapLen = 262144

func writePcapHeader(w io.Writer, snapLen int) {
	binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // pcap magic number
	binary.Write(w, binary.LittleEndian, uint16(2))          // version major
	binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
	binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
	binary.Write(w, binary.LittleEndian, uint32(0))          // zone significant figures
	binary.Write(w, binary.LittleEndian, uint32(snapLen))    // snapshot length
	binary.Write(w, binary.LittleEndian, uint32(147))        // link-layer ID - USER0
}

func writePktHeader(w *bytes.Buffer, when time.Time, inclLen, origLen int) {
	s := when.Unix()
	us := when.UnixMicro() - (s * 1000000)

	binary.Write(w, binary.LittleEndian, uint32(s))       // timestamp in seconds
	binary.Write(w, binary.LittleEndian, uint32(us))      // timestamp microseconds
	binary.Write(w, binary.LittleEndian, uint32(inclLen)) // number of octets of packet saved
	binary.Write(w, binary.LittleEndian, uint32(origLen)) // actual length of packet
}

// newSink creates a new capture sink that stores at most snapLen bytes of each
// captured packet. A snapLen <= 0 uses [defaultSnapLen].
func newSink(snapLen int) packet.CaptureSink {
	if snapLen <= 0 {
		snapLen = defaultSnapLen
	}
	ctx, c := context.WithCancel(context.Background())
	return &Sink{
		ctx:       ctx,
		ctxCancel: c,
		snapLen:   snapLen,
	}
}

// Type Sink handles callbacks with packets to be logged,
// formatting them into a pcap stream which is mirrored to
// all registered outputs.
type Sink struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	// snapLen is the maximum number of bytes stored for each captured packet.
	// It is set once at creation and never mutated afterwards.
	snapLen int

	mu         sync.Mutex
	outputs    set.HandleSet[io.Writer]
	flushTimer *time.Timer // or nil if none running
}

// RegisterOutput connects an output to this sink, which
// will be written to with a pcap stream as packets are logged.
// A function is returned which unregisters the output when
// called.
//
// If w implements io.Closer, it will be closed upon error
// or when the sink is closed. If w implements http.Flusher,
// it will be flushed periodically.
func (s *Sink) RegisterOutput(w io.Writer) (unregister func()) {
	select {
	case <-s.ctx.Done():
		return func() {}
	default:
	}

	writePcapHeader(w, s.snapLen)
	s.mu.Lock()
	hnd := s.outputs.Add(w)
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.outputs, hnd)
	}
}

func (s *Sink) CaptureCallback() packet.CaptureCallback {
	return s.LogPacket
}

// NumOutputs returns the number of outputs registered with the sink.
func (s *Sink) NumOutputs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.outputs)
}

// Close shuts down the sink. Future calls to LogPacket
// are ignored, and any registered output that implements
// io.Closer is closed.
func (s *Sink) Close() error {
	s.ctxCancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}

	for _, o := range s.outputs {
		if o, ok := o.(io.Closer); ok {
			o.Close()
		}
	}
	s.outputs = nil
	return nil
}

// WaitCh returns a channel which blocks until
// the sink is closed.
func (s *Sink) WaitCh() <-chan struct{} {
	return s.ctx.Done()
}

func customDataLen(meta packet.CaptureMeta) int {
	length := 4
	if meta.DidSNAT {
		length += meta.OriginalSrc.Addr().BitLen() / 8
	}
	if meta.DidDNAT {
		length += meta.OriginalDst.Addr().BitLen() / 8
	}
	return length
}

// LogPacket is called to insert a packet into the capture.
//
// This function does not take ownership of the provided data slice.
func (s *Sink) LogPacket(path packet.CapturePath, when time.Time, data []byte, meta packet.CaptureMeta) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	extraLen := customDataLen(meta)
	origLen := extraLen + len(data)
	inclLen := origLen
	if s.snapLen > 0 && inclLen > s.snapLen {
		inclLen = s.snapLen
	}

	// body holds the record contents (custom metadata followed by the packet
	// payload) so it can be truncated to the snapshot length before the pcap
	// record is written.
	body := bufferPool.Get().(*bytes.Buffer)
	body.Reset()
	body.Grow(origLen)
	defer bufferPool.Put(body)

	// Custom tailscale debugging data
	binary.Write(body, binary.LittleEndian, uint16(path))
	if meta.DidSNAT {
		binary.Write(body, binary.LittleEndian, uint8(meta.OriginalSrc.Addr().BitLen()/8))
		body.Write(meta.OriginalSrc.Addr().AsSlice())
	} else {
		binary.Write(body, binary.LittleEndian, uint8(0)) // SNAT addr len == 0
	}
	if meta.DidDNAT {
		binary.Write(body, binary.LittleEndian, uint8(meta.OriginalDst.Addr().BitLen()/8))
		body.Write(meta.OriginalDst.Addr().AsSlice())
	} else {
		binary.Write(body, binary.LittleEndian, uint8(0)) // DNAT addr len == 0
	}
	body.Write(data)

	b := bufferPool.Get().(*bytes.Buffer)
	b.Reset()
	b.Grow(16 + inclLen) // 16b pcap header + up to snapLen bytes of the record
	defer bufferPool.Put(b)

	writePktHeader(b, when, inclLen, origLen)
	b.Write(body.Bytes()[:inclLen])

	s.mu.Lock()
	defer s.mu.Unlock()

	var hadError []set.Handle
	for hnd, o := range s.outputs {
		if _, err := o.Write(b.Bytes()); err != nil {
			hadError = append(hadError, hnd)
			continue
		}
	}
	for _, hnd := range hadError {
		if o, ok := s.outputs[hnd].(io.Closer); ok {
			o.Close()
		}
		delete(s.outputs, hnd)
	}

	if s.flushTimer == nil {
		s.flushTimer = time.AfterFunc(flushPeriod, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, o := range s.outputs {
				if f, ok := o.(http.Flusher); ok {
					f.Flush()
				}
			}
			s.flushTimer = nil
		})
	}
}
