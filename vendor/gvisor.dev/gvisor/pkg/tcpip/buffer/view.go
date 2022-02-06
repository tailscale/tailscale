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

// Package buffer provides the implementation of a buffer view.
package buffer

import (
	"bytes"
	"fmt"
	"io"
)

// View is a slice of a buffer, with convenience methods.
type View []byte

// NewView allocates a new buffer and returns an initialized view that covers
// the whole buffer.
func NewView(size int) View {
	return make(View, size)
}

// NewViewFromBytes allocates a new buffer and copies in the given bytes.
func NewViewFromBytes(b []byte) View {
	return append(View(nil), b...)
}

// TrimFront removes the first "count" bytes from the visible section of the
// buffer.
func (v *View) TrimFront(count int) {
	*v = (*v)[count:]
}

// CapLength irreversibly reduces the length of the visible section of the
// buffer to the value specified.
func (v *View) CapLength(length int) {
	// We also set the slice cap because if we don't, one would be able to
	// expand the view back to include the region just excluded. We want to
	// prevent that to avoid potential data leak if we have uninitialized
	// data in excluded region.
	*v = (*v)[:length:length]
}

// Reader returns a bytes.Reader for v.
func (v *View) Reader() bytes.Reader {
	var r bytes.Reader
	r.Reset(*v)
	return r
}

// ToVectorisedView returns a VectorisedView containing the receiver.
func (v View) ToVectorisedView() VectorisedView {
	if len(v) == 0 {
		return VectorisedView{}
	}
	return NewVectorisedView(len(v), []View{v})
}

// IsEmpty returns whether v is of length zero.
func (v View) IsEmpty() bool {
	return len(v) == 0
}

// Size returns the length of v.
func (v View) Size() int {
	return len(v)
}

// VectorisedView is a vectorised version of View using non contiguous memory.
// It supports all the convenience methods supported by View.
//
// +stateify savable
type VectorisedView struct {
	views []View
	size  int
}

// NewVectorisedView creates a new vectorised view from an already-allocated
// slice of View and sets its size.
func NewVectorisedView(size int, views []View) VectorisedView {
	return VectorisedView{views: views, size: size}
}

// TrimFront removes the first "count" bytes of the vectorised view. It panics
// if count > vv.Size().
func (vv *VectorisedView) TrimFront(count int) {
	for count > 0 && len(vv.views) > 0 {
		if count < len(vv.views[0]) {
			vv.size -= count
			vv.views[0].TrimFront(count)
			return
		}
		count -= len(vv.views[0])
		vv.removeFirst()
	}
}

// Read implements io.Reader.
func (vv *VectorisedView) Read(b []byte) (copied int, err error) {
	count := len(b)
	for count > 0 && len(vv.views) > 0 {
		if count < len(vv.views[0]) {
			vv.size -= count
			copy(b[copied:], vv.views[0][:count])
			vv.views[0].TrimFront(count)
			copied += count
			return copied, nil
		}
		count -= len(vv.views[0])
		copy(b[copied:], vv.views[0])
		copied += len(vv.views[0])
		vv.removeFirst()
	}
	if copied == 0 {
		return 0, io.EOF
	}
	return copied, nil
}

// ReadToVV reads up to n bytes from vv to dstVV and removes them from vv. It
// returns the number of bytes copied.
func (vv *VectorisedView) ReadToVV(dstVV *VectorisedView, count int) (copied int) {
	for count > 0 && len(vv.views) > 0 {
		if count < len(vv.views[0]) {
			vv.size -= count
			dstVV.AppendView(vv.views[0][:count])
			vv.views[0].TrimFront(count)
			copied += count
			return
		}
		count -= len(vv.views[0])
		dstVV.AppendView(vv.views[0])
		copied += len(vv.views[0])
		vv.removeFirst()
	}
	return copied
}

// ReadTo reads up to count bytes from vv to dst. It also removes them from vv
// unless peek is true.
func (vv *VectorisedView) ReadTo(dst io.Writer, peek bool) (int, error) {
	var err error
	done := 0
	for _, v := range vv.Views() {
		var n int
		n, err = dst.Write(v)
		done += n
		if err != nil {
			break
		}
		if n != len(v) {
			panic(fmt.Sprintf("io.Writer.Write succeeded with incomplete write: %d != %d", n, len(v)))
		}
	}
	if !peek {
		vv.TrimFront(done)
	}
	return done, err
}

// CapLength irreversibly reduces the length of the vectorised view.
func (vv *VectorisedView) CapLength(length int) {
	if length < 0 {
		length = 0
	}
	if vv.size < length {
		return
	}
	vv.size = length
	for i := range vv.views {
		v := &vv.views[i]
		if len(*v) >= length {
			if length == 0 {
				vv.views = vv.views[:i]
			} else {
				v.CapLength(length)
				vv.views = vv.views[:i+1]
			}
			return
		}
		length -= len(*v)
	}
}

// Clone returns a clone of this VectorisedView.
// If the buffer argument is large enough to contain all the Views of this
// VectorisedView, the method will avoid allocations and use the buffer to
// store the Views of the clone.
func (vv VectorisedView) Clone(buffer []View) VectorisedView {
	return VectorisedView{views: append(buffer[:0], vv.views...), size: vv.size}
}

// PullUp returns the first "count" bytes of the vectorised view. If those
// bytes aren't already contiguous inside the vectorised view, PullUp will
// reallocate as needed to make them contiguous. PullUp fails and returns false
// when count > vv.Size().
func (vv *VectorisedView) PullUp(count int) (View, bool) {
	if len(vv.views) == 0 {
		return nil, count == 0
	}
	if count <= len(vv.views[0]) {
		return vv.views[0][:count], true
	}
	if count > vv.size {
		return nil, false
	}

	newFirst := NewView(count)
	i := 0
	for offset := 0; offset < count; i++ {
		copy(newFirst[offset:], vv.views[i])
		if count-offset < len(vv.views[i]) {
			vv.views[i].TrimFront(count - offset)
			break
		}
		offset += len(vv.views[i])
		vv.views[i] = nil
	}
	// We're guaranteed that i > 0, since count is too large for the first
	// view.
	vv.views[i-1] = newFirst
	vv.views = vv.views[i-1:]
	return newFirst, true
}

// Size returns the size in bytes of the entire content stored in the
// vectorised view.
func (vv *VectorisedView) Size() int {
	return vv.size
}

// MemSize returns the estimation size of the vv in memory, including backing
// buffer data.
func (vv *VectorisedView) MemSize() int {
	var size int
	for _, v := range vv.views {
		size += cap(v)
	}
	return size + cap(vv.views)*viewStructSize + vectorisedViewStructSize
}

// ToView returns a single view containing the content of the vectorised view.
//
// If the vectorised view contains a single view, that view will be returned
// directly.
func (vv *VectorisedView) ToView() View {
	if len(vv.views) == 1 {
		return vv.views[0]
	}
	return vv.ToOwnedView()
}

// ToOwnedView returns a single view containing the content of the vectorised
// view that vv does not own.
func (vv *VectorisedView) ToOwnedView() View {
	u := make([]byte, 0, vv.size)
	for _, v := range vv.views {
		u = append(u, v...)
	}
	return u
}

// Views returns the slice containing the all views.
func (vv *VectorisedView) Views() []View {
	return vv.views
}

// Append appends the views in a vectorised view to this vectorised view.
func (vv *VectorisedView) Append(vv2 VectorisedView) {
	vv.views = append(vv.views, vv2.views...)
	vv.size += vv2.size
}

// AppendView appends the given view into this vectorised view.
func (vv *VectorisedView) AppendView(v View) {
	if len(v) == 0 {
		return
	}
	vv.views = append(vv.views, v)
	vv.size += len(v)
}

// AppendViews appends views to vv.
func (vv *VectorisedView) AppendViews(views []View) {
	vv.views = append(vv.views, views...)
	for _, v := range views {
		vv.size += len(v)
	}
}

// Readers returns a bytes.Reader for each of vv's views.
func (vv *VectorisedView) Readers() []bytes.Reader {
	readers := make([]bytes.Reader, 0, len(vv.views))
	for _, v := range vv.views {
		readers = append(readers, v.Reader())
	}
	return readers
}

// removeFirst panics when len(vv.views) < 1.
func (vv *VectorisedView) removeFirst() {
	vv.size -= len(vv.views[0])
	vv.views[0] = nil
	vv.views = vv.views[1:]
}
