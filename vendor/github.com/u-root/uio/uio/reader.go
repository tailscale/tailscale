// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uio

import (
	"bytes"
	"io"
	"io/ioutil"
	"math"
	"reflect"
)

type inMemReaderAt interface {
	Bytes() []byte
}

// ReadAll reads everything that r contains.
//
// Callers *must* not modify bytes in the returned byte slice.
//
// If r is an in-memory representation, ReadAll will attempt to return a
// pointer to those bytes directly.
func ReadAll(r io.ReaderAt) ([]byte, error) {
	if imra, ok := r.(inMemReaderAt); ok {
		return imra.Bytes(), nil
	}
	return ioutil.ReadAll(Reader(r))
}

// Reader generates a Reader from a ReaderAt.
func Reader(r io.ReaderAt) io.Reader {
	return io.NewSectionReader(r, 0, math.MaxInt64)
}

// ReaderAtEqual compares the contents of r1 and r2.
func ReaderAtEqual(r1, r2 io.ReaderAt) bool {
	var c, d []byte
	var r1err, r2err error
	if r1 != nil {
		c, r1err = ReadAll(r1)
	}
	if r2 != nil {
		d, r2err = ReadAll(r2)
	}
	return bytes.Equal(c, d) && reflect.DeepEqual(r1err, r2err)
}
