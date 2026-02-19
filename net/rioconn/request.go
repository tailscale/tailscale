// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn/winrio"
	"golang.org/x/sys/windows"
)

// request represents a portion of a RIO-registered memory buffer used for
// a single send or receive operation. It is always heap-allocated, and the
// fixed-size struct is followed in memory by a variable-size data buffer.
//
// A memory buffer implementation, such as a [requestRing], is responsible for
// allocating requests within a registered buffer via [unsafeMapRequest] and
// ensuring that the buffer remains registered and valid for the lifetime
// of the requests.
type request struct {
	buffID   winrio.BufferId // ID of the registered buffer containing this request
	buffBase uintptr         // base address of the registered buffer

	raddr rawSockaddr // remote address for RIO send/receive operations
	data  []byte      // a slice pointing into the data buffer area after the struct
	// followed by the actual data at [requestDataOffset]
	// from the start of the struct.
}

const (
	requestDataAlignment = 8
	requestDataOffset    = (unsafe.Sizeof(request{}) + requestDataAlignment - 1) &^ (requestDataAlignment - 1)
)

// totalRequestSize returns the total number of bytes required to hold
// a [request] struct followed by a data buffer of the given size.
func totalRequestSize(dataSize uintptr) uintptr {
	return alignUp(requestDataOffset+dataSize, unsafe.Alignof(request{}))
}

// unsafeMapRequest maps a [request] into the given RIO-registered buffer at the
// specified offset and returns a pointer to it, the number of bytes used,
// and whether the mapping succeeded.
//
// On success, the returned pointer is aligned to the [request]'s natural
// alignment and the request can hold up to dataSize bytes of data.
//
// It is the caller's responsibility to ensure that the buffer remains
// registered and valid for the lifetime of the returned request.
func unsafeMapRequest(buffID winrio.BufferId, buff []byte, offset, dataSize uintptr) (_ *request, n uintptr, ok bool) {
	baseAddr := uintptr(unsafe.Pointer(unsafe.SliceData(buff)))
	alignedOffset := alignUpOffset(baseAddr, offset, unsafe.Alignof(request{}))
	bytesNeeded := totalRequestSize(dataSize) + uintptr(alignedOffset-offset)
	if offset >= uintptr(len(buff)) {
		return nil, 0, false
	}
	bytesAvailable := uintptr(len(buff)) - offset
	if bytesAvailable < bytesNeeded {
		return nil, 0, false
	}

	requestBytes := unsafe.SliceData(buff[alignedOffset:])
	request := (*request)(unsafe.Pointer(requestBytes))
	request.buffID = buffID
	request.buffBase = baseAddr
	request.data = unsafe.Slice(
		(*byte)(unsafe.Add(unsafe.Pointer(request), requestDataOffset)),
		dataSize,
	)[:0] // zero-length data slice with capacity of dataSize
	return request, bytesNeeded, true
}

// Writer returns a [requestWriter] for the request.
func (r *request) Writer() *requestWriter {
	return (*requestWriter)(r)
}

// Reader returns a [requestReader] for the request.
func (r *request) Reader() *requestReader {
	return (*requestReader)(r)
}

// PostSend posts the request as a send operation to the given RIO request queue
// with the specified flags.
func (r *request) PostSend(rq winrio.Rq, flags uint32) error {
	data := winrio.Buffer{
		Id:     r.buffID,
		Length: uint32(len(r.data)),
		Offset: uint32(uintptr(unsafe.Pointer(unsafe.SliceData(r.data))) - r.buffBase),
	}
	remoteAddr := r.remoteAddrDesc()
	return winrio.SendEx(rq, &data, 1, nil, &remoteAddr, nil, nil, flags, uintptr(unsafe.Pointer(r)))
}

// PostReceive posts the request as a receive operation to the given RIO request queue
// with the specified flags.
func (r *request) PostReceive(rq winrio.Rq, flags uint32) error {
	r.data = r.data[:0]
	data := winrio.Buffer{
		Id:     r.buffID,
		Length: uint32(cap(r.data)),
		Offset: uint32(uintptr(unsafe.Pointer(unsafe.SliceData(r.data))) - r.buffBase),
	}
	remoteAddress := r.remoteAddrDesc()
	return winrio.ReceiveEx(rq, &data, 1, nil, &remoteAddress, nil,
		nil, flags, uintptr(unsafe.Pointer(r)))
}

// CompleteSend finalizes a send request.
//
// It validates the completion status and the number of bytes written,
// returning an error if the status indicates a failure, or if the number
// of bytes written does not match the length of the request's data buffer.
func (r *request) CompleteSend(status int32, bytesWritten uint32) error {
	expected := len(r.data)
	if status != 0 {
		return windows.Errno(status)
	}
	if uint64(bytesWritten) != uint64(expected) {
		return fmt.Errorf(
			"bytes written (%d) does not match data buffer length (%d)",
			bytesWritten,
			expected,
		)
	}
	return nil
}

// CompleteReceive finalizes a receive request.
//
// It validates the completion status and the number of bytes read
// returning an error if the status indicates a failure, or if the number
// of bytes read exceeds the capacity of the request's data buffer.
//
// On success, it returns a reader view of the request.
func (r *request) CompleteReceive(status int32, bytesRead uint32) (*requestReader, error) {
	if status != 0 {
		return nil, windows.Errno(status)
	}
	if uint64(bytesRead) > uint64(cap(r.data)) {
		return nil, fmt.Errorf(
			"bytes read (%d) exceeds data buffer capacity (%d)",
			bytesRead,
			cap(r.data),
		)
	}
	r.data = r.data[:bytesRead]
	return r.Reader(), nil
}

func (r *request) remoteAddrDesc() winrio.Buffer {
	return winrio.Buffer{
		Id:     r.buffID,
		Length: uint32(unsafe.Sizeof(r.raddr)),
		Offset: uint32(uintptr(unsafe.Pointer(&r.raddr)) - r.buffBase),
	}
}

// Reset prepares the request for reuse by resetting its state.
func (r *request) Reset() {
	r.raddr = rawSockaddr{}
	r.data = r.data[:0]
}

type (
	requestWriter request
	requestReader request
)

// Len returns the number of bytes written or reserved so far.
func (w *requestWriter) Len() int {
	return len(w.data)
}

// Cap returns the maximum number of bytes that can be written or reserved.
func (w *requestWriter) Cap() int {
	return cap(w.data)
}

// Available returns the number of bytes available for writing or reserving.
func (w *requestWriter) Available() int {
	return cap(w.data) - len(w.data)
}

// SetRemoteAddrPort sets the remote address for the request from a [netip.AddrPort].
// It returns an error if the specified address cannot converted to a [rawSockaddr].
func (w *requestWriter) SetRemoteAddrPort(raddr netip.AddrPort) error {
	var err error
	w.raddr, err = rawSockaddrFromAddrPort(raddr)
	return err
}

// SetRemoteAddr sets the remote address for the request from a [rawSockaddr].
func (w *requestWriter) SetRemoteAddr(raddr rawSockaddr) {
	w.raddr = raddr
}

// Reserve reserves n bytes in the request's data buffer,
// and returns a slice pointing to the reserved space.
// It panics if n is negative or exceeds the available capacity.
func (w *requestWriter) Reserve(n int) []byte {
	if n < 0 {
		panic(fmt.Errorf("cannot reserve negative bytes: %d", n))
	}
	if avail := w.Available(); n > avail {
		panic(fmt.Errorf("cannot reserve %d bytes: only %d available", n, avail))
	}
	oldLen := len(w.data)
	newLen := oldLen + n
	w.data = w.data[:newLen]
	return w.data[oldLen:newLen:newLen] // prevent reslicing beyond newLen
}

// Write implements [io.Writer].
func (w *requestWriter) Write(p []byte) (n int, err error) {
	if len(p) > w.Available() {
		return 0, errors.New("not enough space to write data")
	}
	oldLen := len(w.data)
	newLen := oldLen + len(p)
	w.data = w.data[:newLen]
	copy(w.data[oldLen:], p)
	return len(p), nil
}

// SetLen sets the length of the request's data buffer to n.
// It panics if n is negative or exceeds the number of bytes written.
func (w *requestWriter) SetLen(n int) {
	if n < 0 {
		panic(fmt.Errorf("cannot set negative data length: %d", n))
	}
	if n > len(w.data) {
		panic(fmt.Errorf("data length %d exceeds the number of bytes written (%d)", n, len(w.data)))
	}
	w.data = w.data[:n]
}

// Len returns the number of bytes available to read.
func (r *requestReader) Len() int {
	return len(r.data)
}

// Bytes returns the request's payload data.
func (r *requestReader) Bytes() []byte {
	return r.data[:len(r.data):len(r.data)] // prevent reslicing beyond len
}

// RemoteAddrPort returns the request's remote address as a [netip.AddrPort].
func (r *requestReader) RemoteAddrPort() (netip.AddrPort, error) {
	return r.raddr.ToAddrPort()
}

// RemoteAddr returns the request's remote address as an [rawSockaddr].
// It is more efficient than [requestReader.RemoteAddrPort] if the caller
// only needs the raw socket address.
func (r *requestReader) RemoteAddr() rawSockaddr {
	return r.raddr
}
