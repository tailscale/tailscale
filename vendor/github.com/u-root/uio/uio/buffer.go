// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uio

import (
	"encoding/binary"
	"fmt"

	"github.com/u-root/uio/ubinary"
)

// Marshaler is the interface implemented by an object that can marshal itself
// into binary form.
//
// Marshal appends data to the buffer b.
type Marshaler interface {
	Marshal(l *Lexer)
}

// Unmarshaler is the interface implemented by an object that can unmarshal a
// binary representation of itself.
//
// Unmarshal Consumes data from the buffer b.
type Unmarshaler interface {
	Unmarshal(l *Lexer) error
}

// ToBytes marshals m in the given byte order.
func ToBytes(m Marshaler, order binary.ByteOrder) []byte {
	l := NewLexer(NewBuffer(nil), order)
	m.Marshal(l)
	return l.Data()
}

// FromBytes unmarshals b into obj in the given byte order.
func FromBytes(obj Unmarshaler, b []byte, order binary.ByteOrder) error {
	l := NewLexer(NewBuffer(b), order)
	return obj.Unmarshal(l)
}

// ToBigEndian marshals m to big endian byte order.
func ToBigEndian(m Marshaler) []byte {
	l := NewBigEndianBuffer(nil)
	m.Marshal(l)
	return l.Data()
}

// FromBigEndian unmarshals b into obj in big endian byte order.
func FromBigEndian(obj Unmarshaler, b []byte) error {
	l := NewBigEndianBuffer(b)
	return obj.Unmarshal(l)
}

// ToLittleEndian marshals m to little endian byte order.
func ToLittleEndian(m Marshaler) []byte {
	l := NewLittleEndianBuffer(nil)
	m.Marshal(l)
	return l.Data()
}

// FromLittleEndian unmarshals b into obj in little endian byte order.
func FromLittleEndian(obj Unmarshaler, b []byte) error {
	l := NewLittleEndianBuffer(b)
	return obj.Unmarshal(l)
}

// Buffer implements functions to manipulate byte slices in a zero-copy way.
type Buffer struct {
	// data is the underlying data.
	data []byte

	// byteCount keeps track of how many bytes have been consumed for
	// debugging.
	byteCount int
}

// NewBuffer Consumes b for marshaling or unmarshaling in the given byte order.
func NewBuffer(b []byte) *Buffer {
	return &Buffer{data: b}
}

// Preallocate increases the capacity of the buffer by n bytes.
func (b *Buffer) Preallocate(n int) {
	b.data = append(b.data, make([]byte, 0, n)...)
}

// WriteN appends n bytes to the Buffer and returns a slice pointing to the
// newly appended bytes.
func (b *Buffer) WriteN(n int) []byte {
	b.data = append(b.data, make([]byte, n)...)
	return b.data[len(b.data)-n:]
}

// ReadN consumes n bytes from the Buffer. It returns nil, false if there
// aren't enough bytes left.
func (b *Buffer) ReadN(n int) ([]byte, error) {
	if !b.Has(n) {
		return nil, fmt.Errorf("buffer too short at position %d: have %d bytes, want %d bytes", b.byteCount, b.Len(), n)
	}
	rval := b.data[:n]
	b.data = b.data[n:]
	b.byteCount += n
	return rval, nil
}

// Data is unConsumed data remaining in the Buffer.
func (b *Buffer) Data() []byte {
	return b.data
}

// Has returns true if n bytes are available.
func (b *Buffer) Has(n int) bool {
	return len(b.data) >= n
}

// Len returns the length of the remaining bytes.
func (b *Buffer) Len() int {
	return len(b.data)
}

// Cap returns the available capacity.
func (b *Buffer) Cap() int {
	return cap(b.data)
}

// Lexer is a convenient encoder/decoder for buffers.
//
// Use:
//
//   func (s *something) Unmarshal(l *Lexer) {
//     s.Foo = l.Read8()
//     s.Bar = l.Read8()
//     s.Baz = l.Read16()
//     return l.Error()
//   }
type Lexer struct {
	*Buffer

	// order is the byte order to write in / read in.
	order binary.ByteOrder

	// err
	err error
}

// NewLexer returns a new coder for buffers.
func NewLexer(b *Buffer, order binary.ByteOrder) *Lexer {
	return &Lexer{
		Buffer: b,
		order:  order,
	}
}

// NewLittleEndianBuffer returns a new little endian coder for a new buffer.
func NewLittleEndianBuffer(b []byte) *Lexer {
	return &Lexer{
		Buffer: NewBuffer(b),
		order:  binary.LittleEndian,
	}
}

// NewBigEndianBuffer returns a new big endian coder for a new buffer.
func NewBigEndianBuffer(b []byte) *Lexer {
	return &Lexer{
		Buffer: NewBuffer(b),
		order:  binary.BigEndian,
	}
}

// NewNativeEndianBuffer returns a new native endian coder for a new buffer.
func NewNativeEndianBuffer(b []byte) *Lexer {
	return &Lexer{
		Buffer: NewBuffer(b),
		order:  ubinary.NativeEndian,
	}
}

func (l *Lexer) setError(err error) {
	if l.err == nil {
		l.err = err
	}
}

// Consume returns a slice of the next n bytes from the buffer.
//
// Consume gives direct access to the underlying data.
func (l *Lexer) Consume(n int) []byte {
	v, err := l.Buffer.ReadN(n)
	if err != nil {
		l.setError(err)
		return nil
	}
	return v
}

func (l *Lexer) append(n int) []byte {
	return l.Buffer.WriteN(n)
}

// Error returns an error if an error occurred reading from the buffer.
func (l *Lexer) Error() error {
	return l.err
}

// FinError returns an error if an error occurred or if there is more data left
// to read in the buffer.
func (l *Lexer) FinError() error {
	if l.err != nil {
		return l.err
	}
	if l.Buffer.Len() > 0 {
		return fmt.Errorf("buffer contains more bytes than it should")
	}
	return nil
}

// Read8 reads a byte from the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Read8() uint8 {
	v := l.Consume(1)
	if v == nil {
		return 0
	}
	return uint8(v[0])
}

// Read16 reads a 16-bit value from the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Read16() uint16 {
	v := l.Consume(2)
	if v == nil {
		return 0
	}
	return l.order.Uint16(v)
}

// Read32 reads a 32-bit value from the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Read32() uint32 {
	v := l.Consume(4)
	if v == nil {
		return 0
	}
	return l.order.Uint32(v)
}

// Read64 reads a 64-bit value from the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Read64() uint64 {
	v := l.Consume(8)
	if v == nil {
		return 0
	}
	return l.order.Uint64(v)
}

// CopyN returns a copy of the next n bytes.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) CopyN(n int) []byte {
	v := l.Consume(n)
	if v == nil {
		return nil
	}

	p := make([]byte, n)
	m := copy(p, v)
	return p[:m]
}

// ReadAll Consumes and returns a copy of all remaining bytes in the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) ReadAll() []byte {
	return l.CopyN(l.Len())
}

// ReadBytes reads exactly len(p) values from the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) ReadBytes(p []byte) {
	copy(p, l.Consume(len(p)))
}

// Read implements io.Reader.Read.
func (l *Lexer) Read(p []byte) (int, error) {
	v := l.Consume(len(p))
	if v == nil {
		return 0, l.Error()
	}
	return copy(p, v), nil
}

// ReadData reads the binary representation of data from the buffer.
//
// See binary.Read.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) ReadData(data interface{}) {
	l.setError(binary.Read(l, l.order, data))
}

// WriteData writes a binary representation of data to the buffer.
//
// See binary.Write.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) WriteData(data interface{}) {
	l.setError(binary.Write(l, l.order, data))
}

// Write8 writes a byte to the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Write8(v uint8) {
	l.append(1)[0] = byte(v)
}

// Write16 writes a 16-bit value to the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Write16(v uint16) {
	l.order.PutUint16(l.append(2), v)
}

// Write32 writes a 32-bit value to the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Write32(v uint32) {
	l.order.PutUint32(l.append(4), v)
}

// Write64 writes a 64-bit value to the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Write64(v uint64) {
	l.order.PutUint64(l.append(8), v)
}

// Append returns a newly appended n-size Buffer to write to.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Append(n int) []byte {
	return l.append(n)
}

// WriteBytes writes p to the Buffer.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) WriteBytes(p []byte) {
	copy(l.append(len(p)), p)
}

// Write implements io.Writer.Write.
//
// If an error occurred, Error() will return a non-nil error.
func (l *Lexer) Write(p []byte) (int, error) {
	return copy(l.append(len(p)), p), nil
}

// Align appends bytes to align the length of the buffer to be divisible by n.
func (l *Lexer) Align(n int) {
	pad := ((l.Len() + n - 1) &^ (n - 1)) - l.Len()
	l.Append(pad)
}
