// Copyright 2020 The gVisor Authors.
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

// Package buffer provides the implementation of a buffer view.
//
// A view is an flexible buffer, supporting the safecopy operations natively as
// well as the ability to grow via either prepend or append, as well as shrink.
package buffer

// buffer encapsulates a queueable byte buffer.
//
// +stateify savable
type buffer struct {
	data  []byte
	read  int
	write int
	bufferEntry
}

// init performs in-place initialization for zero value.
func (b *buffer) init(size int) {
	b.data = make([]byte, size)
}

// initWithData initializes b with data, taking ownership.
func (b *buffer) initWithData(data []byte) {
	b.data = data
	b.read = 0
	b.write = len(data)
}

// Reset resets read and write locations, effectively emptying the buffer.
func (b *buffer) Reset() {
	b.read = 0
	b.write = 0
}

// Remove removes r from the unread portion. It returns false if r does not
// fully reside in b.
func (b *buffer) Remove(r Range) bool {
	sz := b.ReadSize()
	switch {
	case r.Len() != r.Intersect(Range{end: sz}).Len():
		return false
	case r.Len() == 0:
		// Noop
	case r.begin == 0:
		b.read += r.end
	case r.end == sz:
		b.write -= r.Len()
	default:
		// Remove from the middle of b.data.
		copy(b.data[b.read+r.begin:], b.data[b.read+r.end:b.write])
		b.write -= r.Len()
	}
	return true
}

// Full indicates the buffer is full.
//
// This indicates there is no capacity left to write.
func (b *buffer) Full() bool {
	return b.write == len(b.data)
}

// ReadSize returns the number of bytes available for reading.
func (b *buffer) ReadSize() int {
	return b.write - b.read
}

// ReadMove advances the read index by the given amount.
func (b *buffer) ReadMove(n int) {
	b.read += n
}

// ReadSlice returns the read slice for this buffer.
func (b *buffer) ReadSlice() []byte {
	return b.data[b.read:b.write]
}

// WriteSize returns the number of bytes available for writing.
func (b *buffer) WriteSize() int {
	return len(b.data) - b.write
}

// WriteMove advances the write index by the given amount.
func (b *buffer) WriteMove(n int) {
	b.write += n
}

// WriteSlice returns the write slice for this buffer.
func (b *buffer) WriteSlice() []byte {
	return b.data[b.write:]
}
