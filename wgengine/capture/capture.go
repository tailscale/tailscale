// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package capture formats packet logging into a debug pcap stream.
package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"sync"
	"time"

	_ "embed"

	"tailscale.com/net/packet"
	"tailscale.com/util/set"
)

//go:embed ts-dissector.lua
var DissectorLua string

// Callback describes a function which is called to
// record packets when debugging packet-capture.
// Such callbacks must not take ownership of the
// provided data slice: it may only copy out of it
// within the lifetime of the function.
type Callback func(Path, time.Time, []byte, packet.CaptureMeta)

var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

const flushPeriod = 100 * time.Millisecond

func writePcapHeader(w io.Writer) {
	binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // pcap magic number
	binary.Write(w, binary.LittleEndian, uint16(2))          // version major
	binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
	binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
	binary.Write(w, binary.LittleEndian, uint32(0))          // zone significant figures
	binary.Write(w, binary.LittleEndian, uint32(65535))      // max packet len
	binary.Write(w, binary.LittleEndian, uint32(147))        // link-layer ID - USER0
}

func writePktHeader(w *bytes.Buffer, when time.Time, length int) {
	s := when.Unix()
	us := when.UnixMicro() - (s * 1000000)

	binary.Write(w, binary.LittleEndian, uint32(s))      // timestamp in seconds
	binary.Write(w, binary.LittleEndian, uint32(us))     // timestamp microseconds
	binary.Write(w, binary.LittleEndian, uint32(length)) // length present
	binary.Write(w, binary.LittleEndian, uint32(length)) // total length
}

// Path describes where in the data path the packet was captured.
type Path uint8

// Valid Path values.
const (
	// FromLocal indicates the packet was logged as it traversed the FromLocal path:
	// i.e.: A packet from the local system into the TUN.
	FromLocal Path = 0
	// FromPeer indicates the packet was logged upon reception from a remote peer.
	FromPeer Path = 1
	// SynthesizedToLocal indicates the packet was generated from within tailscaled,
	// and is being routed to the local machine's network stack.
	SynthesizedToLocal Path = 2
	// SynthesizedToPeer indicates the packet was generated from within tailscaled,
	// and is being routed to a remote Wireguard peer.
	SynthesizedToPeer Path = 3

	// PathDisco indicates the packet is information about a disco frame.
	PathDisco Path = 254
)

// New creates a new capture sink.
func New() *Sink {
	ctx, c := context.WithCancel(context.Background())
	return &Sink{
		ctx:       ctx,
		ctxCancel: c,
	}
}

// Type Sink handles callbacks with packets to be logged,
// formatting them into a pcap stream which is mirrored to
// all registered outputs.
type Sink struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

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

	writePcapHeader(w)
	s.mu.Lock()
	hnd := s.outputs.Add(w)
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.outputs, hnd)
	}
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
func (s *Sink) LogPacket(path Path, when time.Time, data []byte, meta packet.CaptureMeta) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	extraLen := customDataLen(meta)
	b := bufferPool.Get().(*bytes.Buffer)
	b.Reset()
	b.Grow(16 + extraLen + len(data)) // 16b pcap header + len(metadata) + len(payload)
	defer bufferPool.Put(b)

	writePktHeader(b, when, len(data)+extraLen)

	// Custom tailscale debugging data
	binary.Write(b, binary.LittleEndian, uint16(path))
	if meta.DidSNAT {
		binary.Write(b, binary.LittleEndian, uint8(meta.OriginalSrc.Addr().BitLen()/8))
		b.Write(meta.OriginalSrc.Addr().AsSlice())
	} else {
		binary.Write(b, binary.LittleEndian, uint8(0)) // SNAT addr len == 0
	}
	if meta.DidDNAT {
		binary.Write(b, binary.LittleEndian, uint8(meta.OriginalDst.Addr().BitLen()/8))
		b.Write(meta.OriginalDst.Addr().AsSlice())
	} else {
		binary.Write(b, binary.LittleEndian, uint8(0)) // DNAT addr len == 0
	}

	b.Write(data)

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
