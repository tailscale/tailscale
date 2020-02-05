// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

type Buffer interface {
	// TryReadLine tries to read a log line from the ring buffer.
	// If no line is available it returns a nil slice.
	// If the ring buffer is closed it returns io.EOF.
	TryReadLine() ([]byte, error)

	// Write writes a log line into the ring buffer.
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

	dropMu    sync.Mutex
	dropCount int
}

func (m *memBuffer) TryReadLine() ([]byte, error) {
	if m.next != nil {
		msg := m.next
		m.next = nil
		return msg, nil
	}

	select {
	case ent := <-m.pending:
		if ent.dropCount > 0 {
			m.next = ent.msg
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "----------- %d logs dropped ----------", ent.dropCount)
			return buf.Bytes(), nil
		}
		return ent.msg, nil
	default:
		return nil, nil
	}
}

func (m *memBuffer) Write(b []byte) (int, error) {
	m.dropMu.Lock()
	defer m.dropMu.Unlock()

	ent := qentry{
		msg:       b,
		dropCount: m.dropCount,
	}
	select {
	case m.pending <- ent:
		m.dropCount = 0
		return len(b), nil
	default:
		m.dropCount++
		return 0, errBufferFull
	}
}

type qentry struct {
	msg       []byte
	dropCount int
}

var errBufferFull = errors.New("logtail: buffer full")
