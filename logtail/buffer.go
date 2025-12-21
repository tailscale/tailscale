// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_logtail

package logtail

import (
	"bytes"
	"errors"
	"expvar"
	"fmt"

	"tailscale.com/metrics"
	"tailscale.com/syncs"
)

type Buffer interface {
	// TryReadLine tries to read a log line from the ring buffer.
	// If no line is available it returns a nil slice.
	// If the ring buffer is closed it returns io.EOF.
	//
	// The returned slice may point to data that will be overwritten
	// by a subsequent call to TryReadLine.
	TryReadLine() ([]byte, error)

	// Write writes a log line into the ring buffer.
	// Implementations must not retain the provided buffer.
	Write([]byte) (int, error)
}

func NewMemoryBuffer(numEntries int) Buffer {
	return &memBuffer{
		pending: make(chan qentry, numEntries),
	}
}

type memBuffer struct {
	next    []byte
	pending chan qentry

	dropMu    syncs.Mutex
	dropCount int

	// Metrics (see [memBuffer.ExpVar] for details).
	writeCalls   expvar.Int
	readCalls    expvar.Int
	writeBytes   expvar.Int
	readBytes    expvar.Int
	droppedBytes expvar.Int
	storedBytes  expvar.Int
}

// ExpVar returns a [metrics.Set] with metrics about the buffer.
//
//   - counter_write_calls: Total number of write calls.
//   - counter_read_calls: Total number of read calls.
//   - counter_write_bytes: Total number of bytes written.
//   - counter_read_bytes: Total number of bytes read.
//   - counter_dropped_bytes: Total number of bytes dropped.
//   - gauge_stored_bytes: Current number of bytes stored in memory.
func (b *memBuffer) ExpVar() expvar.Var {
	m := new(metrics.Set)
	m.Set("counter_write_calls", &b.writeCalls)
	m.Set("counter_read_calls", &b.readCalls)
	m.Set("counter_write_bytes", &b.writeBytes)
	m.Set("counter_read_bytes", &b.readBytes)
	m.Set("counter_dropped_bytes", &b.droppedBytes)
	m.Set("gauge_stored_bytes", &b.storedBytes)
	return m
}

func (m *memBuffer) TryReadLine() ([]byte, error) {
	m.readCalls.Add(1)
	if m.next != nil {
		msg := m.next
		m.next = nil
		m.readBytes.Add(int64(len(msg)))
		m.storedBytes.Add(-int64(len(msg)))
		return msg, nil
	}

	select {
	case ent := <-m.pending:
		if ent.dropCount > 0 {
			m.next = ent.msg
			b := fmt.Appendf(nil, "----------- %d logs dropped ----------", ent.dropCount)
			m.writeBytes.Add(int64(len(b))) // indicate pseudo-injected log message
			m.readBytes.Add(int64(len(b)))
			return b, nil
		}
		m.readBytes.Add(int64(len(ent.msg)))
		m.storedBytes.Add(-int64(len(ent.msg)))
		return ent.msg, nil
	default:
		return nil, nil
	}
}

func (m *memBuffer) Write(b []byte) (int, error) {
	m.writeCalls.Add(1)
	m.dropMu.Lock()
	defer m.dropMu.Unlock()

	ent := qentry{
		msg:       bytes.Clone(b),
		dropCount: m.dropCount,
	}
	select {
	case m.pending <- ent:
		m.writeBytes.Add(int64(len(b)))
		m.storedBytes.Add(+int64(len(b)))
		m.dropCount = 0
		return len(b), nil
	default:
		m.dropCount++
		m.droppedBytes.Add(int64(len(b)))
		return 0, errBufferFull
	}
}

type qentry struct {
	msg       []byte
	dropCount int
}

var errBufferFull = errors.New("logtail: buffer full")
