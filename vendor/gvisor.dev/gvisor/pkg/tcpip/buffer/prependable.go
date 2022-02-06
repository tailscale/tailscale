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

package buffer

// Prependable is a buffer that grows backwards, that is, more data can be
// prepended to it. It is useful when building networking packets, where each
// protocol adds its own headers to the front of the higher-level protocol
// header and payload; for example, TCP would prepend its header to the payload,
// then IP would prepend its own, then ethernet.
type Prependable struct {
	// Buf is the buffer backing the prependable buffer.
	buf View

	// usedIdx is the index where the used part of the buffer begins.
	usedIdx int
}

// NewPrependable allocates a new prependable buffer with the given size.
func NewPrependable(size int) Prependable {
	return Prependable{buf: NewView(size), usedIdx: size}
}

// NewPrependableFromView creates an entirely-used Prependable from a View.
//
// NewPrependableFromView takes ownership of v. Note that since the entire
// prependable is used, further attempts to call Prepend will note that size >
// p.usedIdx and return nil.
func NewPrependableFromView(v View) Prependable {
	return Prependable{buf: v, usedIdx: 0}
}

// NewEmptyPrependableFromView creates a new prependable buffer from a View.
func NewEmptyPrependableFromView(v View) Prependable {
	return Prependable{buf: v, usedIdx: len(v)}
}

// View returns a View of the backing buffer that contains all prepended
// data so far.
func (p Prependable) View() View {
	return p.buf[p.usedIdx:]
}

// UsedLength returns the number of bytes used so far.
func (p Prependable) UsedLength() int {
	return len(p.buf) - p.usedIdx
}

// AvailableLength returns the number of bytes used so far.
func (p Prependable) AvailableLength() int {
	return p.usedIdx
}

// TrimBack removes size bytes from the end.
func (p *Prependable) TrimBack(size int) {
	p.buf = p.buf[:len(p.buf)-size]
}

// Prepend reserves the requested space in front of the buffer, returning a
// slice that represents the reserved space.
func (p *Prependable) Prepend(size int) []byte {
	if size > p.usedIdx {
		return nil
	}

	p.usedIdx -= size
	return p.View()[:size:size]
}

// DeepCopy copies p and the bytes backing it.
func (p Prependable) DeepCopy() Prependable {
	p.buf = append(View(nil), p.buf...)
	return p
}
