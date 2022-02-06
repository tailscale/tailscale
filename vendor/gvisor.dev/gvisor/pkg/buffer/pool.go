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

package buffer

const (
	// embeddedCount is the number of buffer structures embedded in the pool. It
	// is also the number for overflow allocations.
	embeddedCount = 8

	// defaultBufferSize is the default size for each underlying storage buffer.
	//
	// It is slightly less than two pages. This is done intentionally to ensure
	// that the buffer object aligns with runtime internals. This two page size
	// will effectively minimize internal fragmentation, but still have a large
	// enough chunk to limit excessive segmentation.
	defaultBufferSize = 8144
)

// pool allocates buffer.
//
// It contains an embedded buffer storage for fast path when the number of
// buffers needed is small.
//
// +stateify savable
type pool struct {
	bufferSize      int
	avail           []buffer              `state:"nosave"`
	embeddedStorage [embeddedCount]buffer `state:"wait"`
}

// get gets a new buffer from p.
func (p *pool) get() *buffer {
	buf := p.getNoInit()
	buf.init(p.bufferSize)
	return buf
}

// get gets a new buffer from p without initializing it.
func (p *pool) getNoInit() *buffer {
	if p.avail == nil {
		p.avail = p.embeddedStorage[:]
	}
	if len(p.avail) == 0 {
		p.avail = make([]buffer, embeddedCount)
	}
	if p.bufferSize <= 0 {
		p.bufferSize = defaultBufferSize
	}
	buf := &p.avail[0]
	p.avail = p.avail[1:]
	return buf
}

// put releases buf.
func (p *pool) put(buf *buffer) {
	// Remove reference to the underlying storage, allowing it to be garbage
	// collected.
	buf.data = nil
	buf.Reset()
}

// setBufferSize sets the size of underlying storage buffer for future
// allocations. It can be called at any time.
func (p *pool) setBufferSize(size int) {
	p.bufferSize = size
}

// afterLoad is invoked by stateify.
func (p *pool) afterLoad() {
	// S/R does not save subslice into embeddedStorage correctly. Restore
	// available portion of embeddedStorage manually. Restore as nil if none used.
	for i := len(p.embeddedStorage); i > 0; i-- {
		if p.embeddedStorage[i-1].data != nil {
			p.avail = p.embeddedStorage[i:]
			break
		}
	}
}
