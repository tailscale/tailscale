// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"bytes"
	"net/netip"
	"testing"
	"unsafe"
)

func TestUnsafeMapRequest(t *testing.T) {
	tests := []struct {
		name          string
		buff          []byte
		offset        uintptr
		dataSize      uintptr
		wantOk        bool
		wantOffset    uintptr
		wantBytesUsed uintptr
	}{
		{
			name:          "enough-space",
			buff:          makeAligned(totalRequestSize(10), unsafe.Alignof(request{})),
			dataSize:      10,
			wantOk:        true,
			wantOffset:    0,
			wantBytesUsed: totalRequestSize(10),
		},
		{
			name:          "enough-space/unaligned-buffer",
			buff:          makeMisaligned(totalRequestSize(10)+2, unsafe.Alignof(request{}), 2),
			offset:        0,
			dataSize:      10,
			wantOk:        true,
			wantOffset:    2,                        // the request starts at offset 2 for proper alignment
			wantBytesUsed: totalRequestSize(10) + 2, // includes padding before the request
		},
		{
			name:          "enough-space/unaligned-buffer/aligned-offset",
			buff:          makeMisaligned(totalRequestSize(10)+2, unsafe.Alignof(request{}), 2),
			offset:        2,
			dataSize:      10,
			wantOk:        true,
			wantOffset:    2,                    // same as offset requested
			wantBytesUsed: totalRequestSize(10), // no extra padding needed
		},
		{
			name:          "enough-space/aligned-buffer/non-zero-offset",
			buff:          makeAligned(totalRequestSize(10)+16, unsafe.Alignof(request{})),
			offset:        16,
			dataSize:      10,
			wantOk:        true,
			wantOffset:    16,
			wantBytesUsed: totalRequestSize(10),
		},
		{
			name:   "not-enough-space/nil-buffer",
			buff:   nil,
			wantOk: false,
		},
		{
			name:     "not-enough-space/small-buffer",
			buff:     makeAligned(totalRequestSize(10)-1, unsafe.Alignof(request{})),
			dataSize: 10,
			wantOk:   false,
		},
		{
			name:     "not-enough-space/due-to-offset",
			buff:     makeAligned(totalRequestSize(10), unsafe.Alignof(request{})),
			offset:   8,
			dataSize: 10,
			wantOk:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, bytesUsed, ok := unsafeMapRequest(0, tt.buff, tt.offset, tt.dataSize)
			if ok != tt.wantOk {
				t.Errorf("mapRequest: ok: got %v; want %v", ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if bytesUsed != tt.wantBytesUsed {
				t.Errorf("mapRequest: bytesUsed: got %d; want %d", bytesUsed, tt.wantBytesUsed)
			}
			gotOffset := uintptr(unsafe.Pointer(request)) - uintptr(unsafe.Pointer(&tt.buff[0]))
			if gotOffset != tt.wantOffset {
				t.Errorf("mapRequest: offset: got %d; want %d", gotOffset, tt.wantOffset)
			}
		})
	}
}

func TestRequestWriterReserve(t *testing.T) {
	const dataSize = 1312
	req := makeRequest(t, dataSize)
	writer := req.Writer()

	// The capacity of the writer's data buffer must match the requested data size.
	if gotCap := writer.Cap(); gotCap != dataSize {
		t.Errorf("requestWriter.Cap: got %d; want %d", gotCap, dataSize)
	}

	// Initially, the entire data buffer must be available for writing.
	if gotAvail := writer.Available(); gotAvail != dataSize {
		t.Errorf("requestWriter.Available: got %d; want %d", gotAvail, dataSize)
	}

	// And the length of the data buffer must be zero
	// since nothing has been written or reserved yet.
	if gotLen := writer.Len(); gotLen != 0 {
		t.Errorf("requestWriter.Len: got %d; want %d", gotLen, 0)
	}

	// Reserving more than the available capacity must fail.
	CheckPanic(t, true, func() { writer.Reserve(dataSize + 1) })
	if gotAvail := writer.Available(); gotAvail != dataSize {
		t.Errorf("requestWriter.Available after failed Reserve: got %d; want %d",
			gotAvail, dataSize)
	}

	// Reserving zero bytes must return an empty buffer.
	buf := writer.Reserve(0)
	if len(buf) != 0 {
		t.Errorf("Reserve: got buffer of length %d; want %d", len(buf), 0)
	}
	// The capacity of the returned buffer must also be zero.
	if cap(buf) != 0 {
		t.Errorf("Reserve: got buffer of capacity %d; want %d", cap(buf), 0)
	}

	// Reserving part of the available capacity should succeed.
	buf = writer.Reserve(64)
	if len(buf) != 64 {
		t.Errorf("Reserve: got buffer of length %d; want %d", len(buf), 64)
	}
	// The capacity of the returned buffer should be equal to its length
	// to prevent reslicing beyond the reserved length.
	if cap(buf) != len(buf) {
		t.Errorf("Reserve: got buffer of capacity %d; want %d", cap(buf), len(buf))
	}
	// The returned buffer should point to the start of the writer's data buffer.
	if &buf[0] != &writer.data[0] {
		t.Errorf("Reserve: got buffer starting at %p; want %p", &buf[0], &writer.data[0])
	}
	// After reserving X bytes, the length of the data buffer should be X.
	if writer.Len() != len(buf) {
		t.Errorf("requestWriter.Len after Reserve: got %d; want %d", writer.Len(), len(buf))
	}
	// And the available capacity should decrease by X.
	if gotAvail := writer.Available(); gotAvail != dataSize-len(buf) {
		t.Errorf("requestWriter.Available after Reserve: got %d; want %d",
			gotAvail, dataSize-len(buf))
	}
	// However, the total capacity of the writer's data buffer should remain unchanged.
	if cap(writer.data) != dataSize {
		t.Errorf("requestWriter.data capacity: got %d; want %d", cap(writer.data), dataSize)
	}

	bytesWritten := copy(buf, []byte("Hello World"))

	// SetLen must panic if the desired length exceeds the number of bytes
	// written or reserved so far.
	CheckPanic(t, true, func() { writer.SetLen(len(buf) + 1) })
	// Or if the desired length is negative.
	CheckPanic(t, true, func() { writer.SetLen(-1) })

	// Otherwise, it must succeed and update the length of the data buffer accordingly.
	writer.SetLen(len(buf))
	if writer.Len() != len(buf) { // no change expected
		t.Errorf("requestWriter.Len after SetLen: got %d; want %d", writer.Len(), len(buf))
	}

	// The contents of the data buffer up to the set length should be what was written.
	writer.SetLen(bytesWritten)
	if !bytes.Equal(writer.data, []byte("Hello World")) {
		t.Errorf("requestWriter.data: got %q; want %q", writer.data, "Hello World")
	}

	// Reserving more bytes should succeed and return a buffer starting immediately
	// after the previously reserved and written data.
	newBuf := writer.Reserve(10)
	if &newBuf[0] != &writer.data[bytesWritten] {
		t.Errorf("Reserve: got buffer starting at %p; want %p", &newBuf[0], &writer.data[bytesWritten])
	}
	if writer.Len() != bytesWritten+len(newBuf) {
		t.Errorf("requestWriter.Len after second Reserve: got %d; want %d",
			writer.Len(), bytesWritten+len(newBuf))
	}
}

func TestRequestWriterWrite(t *testing.T) {
	const dataSize = 128
	req := makeRequest(t, dataSize)
	writer := req.Writer()
	n, err := writer.Write([]byte("Hello"))
	if err != nil {
		t.Errorf("requestWriter.Write: unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("requestWriter.Write: got %d bytes written; want %d", n, 5)
	}
	writer.Write([]byte(" World"))
	if !bytes.Equal(writer.data[:11], []byte("Hello World")) {
		t.Errorf("requestWriter.data: got %q; want %q", writer.data[:11], "Hello World")
	}
	if writer.Len() != 11 {
		t.Errorf("requestWriter.Len after Write: got %d; want %d", writer.Len(), 11)
	}
	// Writing more bytes than the available capacity should fail.
	n, err = writer.Write(make([]byte, dataSize))
	if err == nil {
		t.Error("requestWriter.Write: expected error when writing beyond capacity; got nil")
	}
	// We do not allow partial writes, so n should be zero...
	if n != 0 {
		t.Errorf("requestWriter.Write: got %d bytes written; want %d", n, 0)
	}
	// ... and the length should remain unchanged.
	if writer.Len() != 11 {
		t.Errorf("requestWriter.Len after failed Write: got %d; want %d", writer.Len(), 11)
	}
}

func TestRequestWriterSetAddrPort(t *testing.T) {
	const dataSize = 128
	addrPort := netip.MustParseAddrPort("192.0.2.1:1234")

	req := makeRequest(t, dataSize)
	writer := req.Writer()
	err := writer.SetRemoteAddrPort(addrPort)
	if err != nil {
		t.Errorf("requestWriter.SetRemoteAddrPort: unexpected error: %v", err)
	}
	gotAddrPort, err := req.raddr.ToAddrPort()
	if err != nil {
		t.Errorf("request.raddr.ToAddrPort: unexpected error: %v", err)
	}
	if gotAddrPort != addrPort {
		t.Errorf("request.raddr: got %v; want %v", gotAddrPort, addrPort)
	}
}

func TestRequestReader(t *testing.T) {
	const dataSize = 128
	req := makeRequest(t, dataSize)
	reader := req.Reader()
	if reader.Len() != 0 {
		t.Errorf("requestReader.Len: got %d; want %d", reader.Len(), 0)
	}
	if len(reader.Bytes()) != 0 {
		t.Errorf("requestReader.Bytes: got buffer of length %d; want %d", len(reader.Bytes()), 0)
	}

	// Simulate receiving data by directly modifying the request's data buffer and length.
	req.data = req.data[:11]
	copy(req.data, []byte("Hello World"))

	if !bytes.Equal(reader.Bytes(), []byte("Hello World")) {
		t.Errorf("requestReader.Bytes: got %q; want %q", reader.Bytes(), "Hello World")
	}
	if reader.Len() != 11 {
		t.Errorf("requestReader.Len: got %d; want %d", reader.Len(), 11)
	}

	addrPort := netip.MustParseAddrPort("192.0.2.1:1234")
	req.raddr, _ = rawSockaddrFromAddrPort(addrPort)
	gotAddrPort, err := reader.RemoteAddrPort()
	if err != nil {
		t.Errorf("requestReader.RemoteAddrPort: unexpected error: %v", err)
	}
	if gotAddrPort != addrPort {
		t.Errorf("requestReader.RemoteAddrPort: got %v; want %v", gotAddrPort, addrPort)
	}
}

func makeRequest(tb testing.TB, dataSize int) *request {
	tb.Helper()
	buff := makeAligned(totalRequestSize(uintptr(dataSize)), unsafe.Alignof(request{}))
	req, _, ok := unsafeMapRequest(0, buff, 0, uintptr(dataSize))
	if !ok {
		tb.Fatalf("failed to make request of size %d", dataSize)
	}
	return req
}

// makeAligned returns a slice of n bytes such that the address of
// the first byte is aligned to the given alignment.
// Alignment must be a power of two.
func makeAligned(n, alignment uintptr) []byte {
	if n == 0 {
		return nil
	}
	buff := make([]byte, n+alignment-1)
	base := uintptr(unsafe.Pointer(&buff[0]))
	offset := alignUpOffset(base, 0, alignment)
	return buff[offset : offset+uintptr(n)]
}

// makeMisaligned returns a slice of n bytes whose start address is
// misaligned by misalign bytes relative to alignment, such that advancing
// the start address by misalign bytes yields an alignment-aligned address.
// Alignment must be a power of two.
func makeMisaligned(n, alignment, misalign uintptr) []byte {
	if n == 0 {
		return nil
	}
	buff := make([]byte, n+alignment+misalign)
	base := uintptr(unsafe.Pointer(&buff[0]))
	aligned := (base + misalign + alignment - 1) &^ (alignment - 1)
	start := aligned - misalign
	offset := start - base
	return buff[offset : offset+n]
}
