// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package traffic implements the daemon-side JSONL traffic logger.
//
// Each TCP flow handed to/from the application emits at least three
// records:
//
//	{"t":"...","kind":"open","conn_id":"...","dir":"in",...}
//	{"t":"...","kind":"data","conn_id":"...","dir":"app->peer","seq":N,
//	 "len":1460,"payload_b64":"..."}
//	{"t":"...","kind":"close","conn_id":"...","bytes_in":..,"bytes_out":..,
//	 "duration_ms":..}
//
// Data records are chunked at MaxChunk bytes so a single record never
// grows unreasonably.
package traffic

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// MaxChunk is the largest payload, in bytes, that fits in a single
// data record. Longer reads/writes are split into multiple records.
const MaxChunk = 16 * 1024

// Direction is one of "in" or "out" (open/close) or "app->peer" /
// "peer->app" (data).
type Direction string

const (
	DirIn      Direction = "in"
	DirOut     Direction = "out"
	DirAppPeer Direction = "app->peer"
	DirPeerApp Direction = "peer->app"
)

// Logger is a thread-safe JSONL writer.
type Logger struct {
	mu     sync.Mutex
	w      *os.File
	closed bool
}

// New opens path for append, creating it with mode 0o600 if it doesn't
// exist.
func New(path string) (*Logger, error) {
	if path == "" {
		// Fall back to a discard logger.
		return &Logger{}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("traffic.New: %w", err)
	}
	return &Logger{w: f}, nil
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.w != nil {
		return l.w.Close()
	}
	return nil
}

func (l *Logger) write(rec map[string]any) {
	if l == nil || l.w == nil {
		return
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return
	}
	buf = append(buf, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	_, _ = l.w.Write(buf)
}

// Open emits an "open" record. Extra fields (e.g. whois) can be passed
// via extra.
func (l *Logger) Open(connID string, dir Direction, proto, local, remote, listenerID string, extra map[string]any) {
	rec := map[string]any{
		"t":       time.Now().UTC().Format(time.RFC3339Nano),
		"kind":    "open",
		"conn_id": connID,
		"dir":     string(dir),
		"proto":   proto,
		"local":   local,
		"remote":  remote,
	}
	if listenerID != "" {
		rec["listener_id"] = listenerID
	}
	for k, v := range extra {
		rec[k] = v
	}
	l.write(rec)
}

// Close emits a "close" record with totals.
func (l *Logger) Close_(connID string, bytesIn, bytesOut int64, dur time.Duration, errStr string) {
	rec := map[string]any{
		"t":           time.Now().UTC().Format(time.RFC3339Nano),
		"kind":        "close",
		"conn_id":     connID,
		"bytes_in":    bytesIn,
		"bytes_out":   bytesOut,
		"duration_ms": dur.Milliseconds(),
	}
	if errStr != "" {
		rec["error"] = errStr
	}
	l.write(rec)
}

// Data emits a single data record. The payload is split at MaxChunk
// boundaries by FlowSink; this method emits one record per call.
func (l *Logger) Data(connID string, dir Direction, seq int, payload []byte) {
	rec := map[string]any{
		"t":           time.Now().UTC().Format(time.RFC3339Nano),
		"kind":        "data",
		"conn_id":     connID,
		"dir":         string(dir),
		"seq":         seq,
		"len":         len(payload),
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
	}
	l.write(rec)
}

// FlowSink is a per-direction byte accumulator that splits writes into
// MaxChunk-sized data records and tracks total bytes.
type FlowSink struct {
	log    *Logger
	connID string
	dir    Direction
	seq    atomic.Int64
	bytes  atomic.Int64
}

// NewFlowSink returns a sink that emits data records for connID/dir.
func NewFlowSink(log *Logger, connID string, dir Direction) *FlowSink {
	return &FlowSink{log: log, connID: connID, dir: dir}
}

// Add accumulates bytes and emits chunked data records.
func (s *FlowSink) Add(p []byte) {
	if s == nil || s.log == nil || s.log.w == nil {
		// Still count bytes so close stats are accurate even when no
		// log file is configured.
		if s != nil {
			s.bytes.Add(int64(len(p)))
		}
		return
	}
	s.bytes.Add(int64(len(p)))
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxChunk {
			chunk = chunk[:MaxChunk]
		}
		seq := int(s.seq.Add(1))
		s.log.Data(s.connID, s.dir, seq, chunk)
		p = p[len(chunk):]
	}
}

// Total reports the total bytes accumulated for this direction.
func (s *FlowSink) Total() int64 {
	if s == nil {
		return 0
	}
	return s.bytes.Load()
}
