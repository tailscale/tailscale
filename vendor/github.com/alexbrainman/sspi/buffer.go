// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package sspi

import (
	"io"
	"unsafe"
)

func (b *SecBuffer) Set(buftype uint32, data []byte) {
	b.BufferType = buftype
	if len(data) > 0 {
		b.Buffer = &data[0]
		b.BufferSize = uint32(len(data))
	} else {
		b.Buffer = nil
		b.BufferSize = 0
	}
}

func (b *SecBuffer) Free() error {
	if b.Buffer == nil {
		return nil
	}
	return FreeContextBuffer((*byte)(unsafe.Pointer(b.Buffer)))
}

func (b *SecBuffer) Bytes() []byte {
	if b.Buffer == nil || b.BufferSize <= 0 {
		return nil
	}
	return (*[(1 << 31) - 1]byte)(unsafe.Pointer(b.Buffer))[:b.BufferSize]
}

func (b *SecBuffer) WriteAll(w io.Writer) (int, error) {
	if b.BufferSize == 0 || b.Buffer == nil {
		return 0, nil
	}
	data := b.Bytes()
	total := 0
	for {
		n, err := w.Write(data)
		total += n
		if err != nil {
			return total, err
		}
		if n >= len(data) {
			break
		}
		data = data[n:]
	}
	return total, nil
}
