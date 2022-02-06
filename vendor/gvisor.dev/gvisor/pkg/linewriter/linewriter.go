// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package linewriter provides an io.Writer which calls an emitter on each line.
package linewriter

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/sync"
)

// Writer is an io.Writer which buffers input, flushing
// individual lines through an emitter function.
type Writer struct {
	// the mutex locks buf.
	sync.Mutex

	// buf holds the data we haven't emitted yet.
	buf bytes.Buffer

	// emit is used to flush individual lines.
	emit func(p []byte)
}

// NewWriter creates a Writer which emits using emitter.
// The emitter must not retain p. It may change after emitter returns.
func NewWriter(emitter func(p []byte)) *Writer {
	return &Writer{emit: emitter}
}

// Write implements io.Writer.Write.
// It calls emit on each line of input, not including the newline.
// Write may be called concurrently.
func (w *Writer) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()

	total := 0
	for len(p) > 0 {
		emit := true
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			// No newline, we will buffer everything.
			i = len(p)
			emit = false
		}

		n, err := w.buf.Write(p[:i])
		if err != nil {
			return total, err
		}
		total += n

		p = p[i:]

		if emit {
			// Skip the newline, but still count it.
			p = p[1:]
			total++

			w.emit(w.buf.Bytes())
			w.buf.Reset()
		}
	}

	return total, nil
}
