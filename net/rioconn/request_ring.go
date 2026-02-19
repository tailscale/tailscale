// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"fmt"
	"iter"
	"math"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn/winrio"
	"golang.org/x/sys/windows"
	"tailscale.com/util/winutil"
)

// requestRing is a circular buffer of [request]s.
// It is not safe for concurrent use.
type requestRing struct {
	capacity  uint32  // number of requests in the ring; always a power of two
	dataSize  uint32  // per-request data buffer length in bytes
	stride    uintptr // byte offset from one request to the next
	indexMask uint32  // masks an index to [0, capacity)

	ptr        uintptr // base address of the ring buffer allocation
	size       uintptr // size of the allocation in bytes
	buff       []byte  // a byte slice view of the allocated buffer
	largePages bool    // whether the allocation used large pages

	head, tail uint32 // monotonic counters; apply &indexMask for indexing

	id winrio.BufferId
}

// When a memory buffer is registered with RIO, the virtual memory pages
// containing the buffer are locked into physical memory.
// Set hard limits to avoid excessive memory usage.
// TODO(nickkhyl): derive preferred values from system parameters?
const (
	maxRequestRingSize  = 1 << 30        // 1 GiB; arbitrary limit
	maxNumberOfRequests = 16384          // arbitrary power-of-two limit
	maxRequestDataSize  = math.MaxUint16 // IP packet size limit
)

// requestStride returns the byte offset from the start of one [request]
// in a [requestRing] to the start of the next, given the per-request data buffer length.
func requestStride(dataSize uint16) uintptr {
	return totalRequestSize(uintptr(dataSize))
}

// maxRequestRingCapacity returns the maximum ring buffer capacity that fits
// within maxBytes, given the per-request data size. The returned capacity
// does not exceed idealCapacity unless idealCapacity is zero, in which case the
// maximum possible value is returned.
//
// dataSize must be in (0, [maxRequestDataSize]], and idealCapacity, if non-zero,
// must be a power of two. The function returns an error if the buffer cannot
//
// It returns an error if the parameters are invalid, if the resulting
// capacity cannot hold at least one request, or if maxBytes exceeds
// [maxRequestRingSize].
func maxRequestRingCapacity(idealCapacity uint32, dataSize uint16, maxBytes uintptr) (uint32, error) {
	if idealCapacity != 0 && !isPowerOfTwo(idealCapacity) {
		return 0, fmt.Errorf("the capacity must be a power of two, got %d", idealCapacity)
	}
	capacity := min(idealCapacity, maxNumberOfRequests)

	if dataSize == 0 || dataSize > maxRequestDataSize {
		return 0, fmt.Errorf("the data size must be in (0, %d], got %d", maxRequestDataSize, dataSize)
	}

	stride := requestStride(dataSize)
	if maxBytes < stride {
		return 0, fmt.Errorf("cannot fit any requests within maxBytes %d", maxBytes)
	}
	if maxBytes > maxRequestRingSize {
		return 0, fmt.Errorf("maxBytes %d exceeds limit of %d", maxBytes, maxRequestRingSize)
	}

	if capacity == 0 || uintptr(capacity)*stride > maxBytes {
		capacity = uint32(floorPowerOfTwo(maxBytes / stride))
	}
	return capacity, nil
}

const (
	// seLockMemoryPrivilege is the name of the Windows privilege required to allocate large pages.
	seLockMemoryPrivilege = "SeLockMemoryPrivilege"
)

// newRequestRing creates a ring buffer of up to maxBytes bytes,
// with each element representing a RIO request backed by a data buffer
// of dataSize bytes.
//
// It determines the buffer capacity as the maximum power-of-two number
// of requests that fits within the allocation size limit, using large
// pages when possible.
//
// If the allocation fails due to insufficient memory, it retries
// with progressively smaller sizes until it succeeds or cannot fit
// at least one request.
//
// The returned buffer is registered with RIO and must be closed with
// [requestRing.Close] to unregister it and free the memory.
func newRequestRing(dataSize uint16, maxBytes uintptr) (_ *requestRing, err error) {
	rb := &requestRing{
		dataSize: uint32(dataSize),
		stride:   requestStride(dataSize),
	}
	defer func() {
		if err != nil {
			rb.Close()
		}
	}()

	var largePageSize uintptr // 0 means "do not use large pages"
	// The SeLockMemoryPrivilege privilege is required to allocate large pages.
	// By default, this privilege can be requested only by processes
	// running as Local System, such as the Tailscale service,
	// and is not available to regular user processes (e.g., when running tests).
	// If enabling the privilege fails, we fall back to normal pages.
	// For testing, you can grant the privilege to your user account
	// using the Local Security Policy management console (secpol.msc).
	dropPrivs, err := winutil.EnableCurrentThreadPrivilege(seLockMemoryPrivilege)
	if err == nil {
		defer dropPrivs()
		largePageSize = windows.GetLargePageMinimum()
	}

loop:
	for {
		capacity, err := maxRequestRingCapacity(0, dataSize, maxBytes)
		if err != nil {
			// The requested parameters are invalid.
			return nil, err
		}

		rb.capacity = uint32(capacity)
		rb.indexMask = uint32(capacity - 1)
		rb.size = rb.stride * uintptr(capacity)

		var largePageFlags uint32
		if largePageSize != 0 {
			if alignedSize := alignUp(rb.size, largePageSize); alignedSize <= maxBytes {
				largePageFlags = windows.MEM_LARGE_PAGES
				rb.size = alignedSize
			}
		}

		rb.ptr, err = windows.VirtualAlloc(
			0, // no preferred address
			rb.size,
			windows.MEM_COMMIT|windows.MEM_RESERVE|largePageFlags,
			windows.PAGE_READWRITE,
		)
		switch err {
		case nil:
			// Allocation succeeded.
			rb.buff = unsafe.Slice((*byte)(unsafe.Pointer(rb.ptr)), rb.size)
			rb.largePages = largePageFlags != 0
			break loop
		case windows.ERROR_NOT_ENOUGH_MEMORY:
			// Try again with a smaller buffer.
			maxBytes /= 2
			continue
		case windows.ERROR_NO_SYSTEM_RESOURCES, windows.ERROR_PRIVILEGE_NOT_HELD:
			// Cannot use large pages, try again without them.
			largePageSize = 0
			continue
		default:
			return nil, fmt.Errorf("failed to allocate request ring buffer: %w", err)
		}
	}

	// The actual RIO initialization is guarded by [sync.Once], and we usually
	// perform it much earlier. We check it here as well to ensure that calling
	// [winrio.RegisterPointer] won't panic (e.g., in tests).
	if err := Initialize(); err != nil {
		return nil, err
	}

	// Register the allocated buffer with RIO.
	if rb.id, err = winrio.RegisterPointer(unsafe.Pointer(unsafe.SliceData(rb.buff)), uint32(rb.size)); err != nil {
		return nil, fmt.Errorf("failed to register request ring buffer with RIO: %w", err)
	}

	// Initialize each request in the ring.
	for i := uintptr(0); i < uintptr(rb.capacity); i++ {
		_, bytesUsed, ok := unsafeMapRequest(rb.id, rb.buff, i*rb.stride, uintptr(dataSize))
		if !ok || bytesUsed != rb.stride {
			// This should never happen.
			panic("failed to map request in newly created request ring")
		}
	}
	return rb, nil
}

// newRequestRingWithCapacity creates a ring buffer with the specified
// power-of-two capacity and per-request data length.
//
// If allocating that many requests exceeds the maximum allowed request ring
// size or fails due to insufficient memory, it retries with progressively
// smaller sizes until it succeeds or cannot fit at least one request.
//
// The caller is responsible for calling [requestRing.close] to free
// the allocated memory when done.
func newRequestRingWithCapacity(dataSize uint16, capacity uint32) (*requestRing, error) {
	if !isPowerOfTwo(capacity) {
		return nil, fmt.Errorf("capacity must be a power of two, got %d", capacity)
	}
	maxSizeInBytes := requestStride(dataSize) * uintptr(capacity)
	return newRequestRing(dataSize, maxSizeInBytes)
}

// Cap returns the total number of requests the ring can hold.
func (rb *requestRing) Cap() uint32 {
	return rb.capacity
}

// Len returns the number requests currently in use (acquired and not yet released).
func (rb *requestRing) Len() uint32 {
	return rb.tail - rb.head
}

// IsEmpty reports whether no requests are currently in use.
func (rb *requestRing) IsEmpty() bool {
	return rb.head == rb.tail
}

// IsFull reports whether all requests are currently in use.
func (rb *requestRing) IsFull() bool {
	return rb.Len() == rb.Cap()
}

// Peek returns the next request without advancing the tail.
// It panics if [requestRing.IsFull] reports true.
func (rb *requestRing) Peek() *request {
	if rb.IsFull() {
		panic("ring is full")
	}
	return rb.peek()
}

// Advance marks the next request as in use by advancing the tail.
// It panics if [requestRing.IsFull] reports true.
func (rb *requestRing) Advance() {
	if rb.IsFull() {
		panic("ring is full")
	}
	rb.tail += 1
}

// Acquire returns the next [request] from the ring, advancing the tail.
// It panics if [requestRing.IsFull] reports true.
func (rb *requestRing) Acquire() *request {
	req := rb.Peek()
	rb.tail += 1
	return req
}

// AcquireSeq yields available [request]s one by one until the ring
// runs out of unused requests or the caller stops the iteration.
func (rb *requestRing) AcquireSeq() iter.Seq[*request] {
	return func(yield func(req *request) bool) {
		end := rb.head + rb.capacity
		for ; rb.tail != end; rb.tail++ {
			if !yield(rb.peek()) {
				return
			}
		}
	}
}

func (rb *requestRing) peek() *request {
	offset := uintptr(rb.tail&rb.indexMask) * rb.stride
	ptr := unsafe.SliceData(rb.buff[offset : offset+rb.stride])
	req := (*request)(unsafe.Pointer(ptr))
	req.Reset()
	return req
}

// ReleaseN marks n requests at the head of the ring as free.
// It is a run-time error to release more requests than have been acquired.
func (rb *requestRing) ReleaseN(n int) {
	if n < 0 {
		panic("ring: negative release count")
	}
	if uint64(n) > uint64(rb.Len()) {
		panic("ring: releasing more requests than acquired")
	}
	rb.head += uint32(n)
}

// Close frees the memory allocated for the request ring.
func (rb *requestRing) Close() error {
	if rb.id != 0 {
		winrio.DeregisterBuffer(rb.id)
		rb.id = 0
	}

	if rb.ptr != 0 {
		if err := windows.VirtualFree(rb.ptr, 0, windows.MEM_RELEASE); err != nil {
			return fmt.Errorf("failed to free request ring buffer: %w", err)
		}
		rb.ptr = 0
	}
	return nil
}
