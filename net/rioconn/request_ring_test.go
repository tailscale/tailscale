// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"fmt"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMaxNumberOfRequestsIsPow2(t *testing.T) {
	if !isPowerOfTwo(maxNumberOfRequests) {
		t.Fatalf("maxNumberOfRRequests %d is not a power of two", maxNumberOfRequests)
	}
}

func TestFloorPowerOfTwo(t *testing.T) {
	tests := []struct {
		n    uint64
		want uint64
	}{
		{0, 0},
		{1, 1},
		{16, 16},
		{17, 16},
		{31, 16},
		{32, 32},
		{uint64(1 << 63), uint64(1 << 63)},
		{uint64(1<<64 - 1), uint64(1) << 63},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x", tt.n), func(t *testing.T) {
			if got := floorPowerOfTwo(tt.n); got != tt.want {
				t.Fatalf("got %d; want %d", got, tt.want)
			}
		})
	}
}

func TestMaxRingBufferCapacity(t *testing.T) {
	tests := []struct {
		name          string
		idealCapacity uint32
		dataSize      uint16
		maxBytes      uintptr
		wantCapacity  uint32
		wantErr       bool
	}{
		{
			name:          "invalid/not-pow2",
			idealCapacity: 3,
			dataSize:      512,
			maxBytes:      65536,
			wantErr:       true,
		},
		{
			name:          "invalid/data-length-zero",
			idealCapacity: 16,
			dataSize:      0,
			maxBytes:      65536,
			wantErr:       true,
		},
		{
			name:          "invalid/max-bytes-too-small",
			idealCapacity: 16,
			dataSize:      512,
			maxBytes:      requestStride(512) - 1, // less than one request
			wantErr:       true,
		},
		{
			name:          "valid/no-clamp",
			idealCapacity: 16,
			dataSize:      512,
			maxBytes:      65536, // can fit [0; 128) requests
			wantCapacity:  16,    // and we asked for 16
		},
		{
			name:          "valid/exact-fit",
			idealCapacity: 16,
			dataSize:      512,
			maxBytes:      requestStride(512) * 16,
			wantCapacity:  16,
		},
		{
			name:          "valid/clamp-down",
			idealCapacity: 128,
			dataSize:      512,
			maxBytes:      requestStride(512) * 64, // can fit only 64 requests
			wantCapacity:  64,                      // clamps down to 64
		},
		{
			name:          "valid/max-requests",
			idealCapacity: 0, // want as many as possible
			dataSize:      512,
			maxBytes:      65536, // can fit [0; 128) requests
			wantCapacity:  64,    // the max power of two that fits
		},
		{
			name:          "valid/large-buffer/no-clamp",
			idealCapacity: 8192,
			dataSize:      maxRequestDataSize,
			maxBytes:      requestStride(maxRequestDataSize) * 8192,
			wantCapacity:  8192,
		},
		{
			name:          "valid/large-buffer/clamp-down",
			idealCapacity: 8192,
			dataSize:      maxRequestDataSize,
			maxBytes:      requestStride(maxRequestDataSize) * 8191, // can fit only 8191
			wantCapacity:  4096,                                     // clamps to next lower power of two
		},
		{
			name:          "invalid/too-many-requests",
			idealCapacity: maxNumberOfRequests * 2,
			dataSize:      512,
			maxBytes:      1 << 30,
			wantCapacity:  maxNumberOfRequests, // cannot exceed [maxNumberOfRRequests]
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maxRequestRingCapacity(tt.idealCapacity, tt.dataSize, uintptr(tt.maxBytes))
			if (err != nil) != tt.wantErr {
				t.Fatalf("maxRingBufferCapacity error: got %v; want %v", err, tt.wantErr)
			}
			if got != tt.wantCapacity {
				t.Fatalf("maxRingBufferCapacity: got %v; want %v", got, tt.wantCapacity)
			}
		})
	}
}

func TestNewRingBuffer(t *testing.T) {
	tests := []struct {
		name           string
		dataSize       uint16
		maxSizeInBytes uintptr
		wantCapacity   uint32
		wantErr        bool
	}{
		{
			name:           "small-buffer",
			dataSize:       256,
			maxSizeInBytes: requestStride(256) * 4,
			wantCapacity:   4,
		},
		{
			name:           "large-buffer/small-requests",
			dataSize:       1280,
			maxSizeInBytes: requestStride(1280) * 8192,
			wantCapacity:   8192,
		},
		{
			name:           "large-buffer/large-requests",
			dataSize:       65535,
			maxSizeInBytes: requestStride(65535) * 32,
			wantCapacity:   32,
		},
		{
			name:           "invalid/limit-too-small",
			dataSize:       256,
			maxSizeInBytes: 100,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb, err := newRequestRing(tt.dataSize, tt.maxSizeInBytes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("newRingBuffer error: got %v; wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			t.Cleanup(func() {
				if err := rb.Close(); err != nil {
					t.Fatalf("ringBuffer.close() failed: %v", err)
				}
			})

			if gotCapacity := rb.Cap(); gotCapacity != tt.wantCapacity {
				t.Errorf("ringBuffer.Cap() = %v; want %v", gotCapacity, tt.wantCapacity)
			}
		})
	}
}

func TestRingBufferAcquireRelease(t *testing.T) {
	tests := []struct {
		name             string
		capacity         uint32
		initialHead      uint32
		initialTail      uint32
		acquires         int
		wantAcquirePanic bool
		releaseN         int
		wantReleasePanic bool
		wantHead         uint32
		wantTail         uint32
		wantDepth        int
	}{
		{
			name:             "empty/acquire-one",
			capacity:         16,
			acquires:         1,
			wantAcquirePanic: false,
			wantTail:         1,
			wantDepth:        1,
		},
		{
			name:             "empty/acquire-few",
			capacity:         16,
			acquires:         4,
			wantAcquirePanic: false,
			wantTail:         4,
			wantDepth:        4,
		},
		{
			name:             "empty/acquire-all",
			capacity:         16,
			acquires:         16,
			wantAcquirePanic: false,
			wantTail:         16,
			wantDepth:        16,
		},
		{
			name:             "empty/acquire-too-many",
			capacity:         16,
			acquires:         17, // one more than the buffer can hold
			wantAcquirePanic: true,
			wantTail:         16,
			wantDepth:        16,
		},
		{
			name:             "empty/release-one",
			capacity:         16,
			releaseN:         1,
			wantReleasePanic: true,
		},
		{
			name:             "partially-full/acquire-few",
			capacity:         16,
			initialTail:      8,
			acquires:         4,
			wantAcquirePanic: false,
			wantTail:         12,
			wantDepth:        8,
		},
		{
			name:             "partially-full/release-few",
			capacity:         16,
			initialTail:      8,
			releaseN:         4,
			wantReleasePanic: false,
			wantHead:         4,
			wantTail:         8,
			wantDepth:        4,
		},
		{
			name:             "partially-full/acquire-all/wrap-around",
			capacity:         16,
			initialHead:      4,
			initialTail:      8,
			acquires:         12,
			wantAcquirePanic: false,
			wantHead:         4,
			wantTail:         20,
			wantDepth:        16,
		},
		{
			name:             "partially-full/acquire-too-many",
			capacity:         16,
			initialHead:      4,
			initialTail:      8,
			acquires:         13, // one more than can fit
			wantAcquirePanic: true,
			wantTail:         20,
			wantHead:         4,
			wantDepth:        16,
		},
		{
			name:             "partially-full/release-too-many",
			capacity:         16,
			initialHead:      4,
			initialTail:      8,
			releaseN:         9, // one more than acquired
			wantReleasePanic: true,
			wantHead:         4,
			wantTail:         8,
		},
		{
			name:             "full/acquire-one",
			capacity:         16,
			initialTail:      16,
			acquires:         1,
			wantAcquirePanic: true,
			wantTail:         16,
		},
		{
			name:             "full/release-one",
			capacity:         16,
			initialTail:      16,
			releaseN:         1,
			wantReleasePanic: false,
			wantHead:         1,
			wantTail:         16,
		},
		{
			name:             "full/release-all",
			capacity:         16,
			initialTail:      16,
			releaseN:         16,
			wantReleasePanic: false,
			wantHead:         16,
			wantTail:         16,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb, err := newRequestRingWithCapacity(4, tt.capacity)
			if err != nil {
				t.Fatalf("newRingBuffer failed: %v", err)
			}
			t.Cleanup(func() { rb.Close() })

			rb.head = uint32(tt.initialHead)
			rb.tail = uint32(tt.initialTail)

			CheckPanic(t, tt.wantAcquirePanic, func() {
				for range tt.acquires {
					_ = rb.Acquire()
				}
			})

			CheckPanic(t, tt.wantReleasePanic, func() {
				rb.ReleaseN(tt.releaseN)
			})

			if rb.head != tt.wantHead {
				t.Fatalf("rb.head = %d; want %d", rb.head, tt.wantHead)
			}
			if rb.tail != tt.wantTail {
				t.Fatalf("rb.tail = %d; want %d", rb.tail, tt.wantTail)
			}
		})
	}
}

func TestRingBufferAcquireSeq(t *testing.T) {
	tests := []struct {
		name        string
		capacity    uint32
		initialHead uint32
		initialTail uint32
		wantTail    uint32
		wantCount   int
	}{
		{
			name:        "empty",
			capacity:    16,
			initialHead: 0,
			initialTail: 0,
			wantTail:    16,
			wantCount:   16, // 16 requests to acquire: [0; 16)
		},
		{
			name:        "partially-full",
			capacity:    16,
			initialHead: 4,
			initialTail: 10,
			wantTail:    20,
			wantCount:   10, // 10 requests to acquire: [10; 15) and [0; 4)
		},
		{
			name:        "full",
			capacity:    16,
			initialHead: 0,
			initialTail: 16,
			wantTail:    16,
			wantCount:   0, // nothing to acquire
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb, err := newRequestRingWithCapacity(4, tt.capacity)
			if err != nil {
				t.Fatalf("newRingBuffer failed: %v", err)
			}
			t.Cleanup(func() { rb.Close() })

			// Initialize head and tail.
			rb.head = tt.initialHead
			rb.tail = tt.initialTail

			// Acquire all available requests and count how many we got.
			gotCount := len(slices.Collect(rb.AcquireSeq()))

			// Check that we got the expected count, the head didn't change,
			// and the tail advanced as expected.
			if gotCount != tt.wantCount {
				t.Fatalf("gotCount = %d; want %d", gotCount, tt.wantCount)
			}
			if rb.head != tt.initialHead {
				t.Fatalf("rb.head = %d; want %d", rb.head, tt.initialHead)
			}
			if rb.tail != tt.wantTail {
				t.Fatalf("rb.tail = %d; want %d", rb.tail, tt.wantTail)
			}
		})
	}
}

func TestRingBufferWrapAround(t *testing.T) {
	const capacity = 16
	rb, err := newRequestRingWithCapacity(4, capacity)
	if err != nil {
		t.Fatalf("newRingBuffer failed: %v", err)
	}
	t.Cleanup(func() { rb.Close() })

	// Acquire all requests and store pointers to them in a slice.
	requests := slices.Collect(rb.AcquireSeq())
	if len(requests) != capacity {
		t.Fatalf("acquired %d requests; want %d", len(requests), capacity)
	}

	rb.ReleaseN(capacity) // release all

	// Acquire again and ensure we get the same requests in the same order.
	for i, wantReq := range requests {
		if gotReq := rb.Acquire(); gotReq != wantReq {
			t.Fatalf("acquired request %d = %p; want %p", i, gotReq, wantReq)
		}
	}
}

// CheckPanic checks whether the given function panics or not,
// and fails the test if the result does not match wantPanic.
func CheckPanic(t *testing.T, wantPanic bool, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if !wantPanic {
				t.Fatalf("unexpected panic: %v", r)
			}
		} else if wantPanic {
			t.Fatal("expected panic but none occurred")
		}
	}()
	fn()
}

// checkProcessPrivilege reports whether the given privilege is present
// and/or enabled in the current process token.
func checkProcessPrivilege(privName string) (present bool, enabled bool, err error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false, false, err
	}
	defer tok.Close()
	return checkTokenPrivilege(tok, privName)
}

// checkTokenPrivilege reports whether the given privilege is present
// and/or enabled in the specified token.
func checkTokenPrivilege(token windows.Token, privName string) (present bool, enabled bool, err error) {
	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(privName)
	if err != nil {
		return false, false, err
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return false, false, err
	}

	var needed uint32
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &needed)
	if needed == 0 {
		return false, false, windows.GetLastError()
	}

	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &needed); err != nil {
		return false, false, err
	}

	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	count := int(tp.PrivilegeCount)

	laa := unsafe.Slice((*windows.LUIDAndAttributes)(unsafe.Pointer(&tp.Privileges[0])), count)
	for _, p := range laa {
		if p.Luid == luid {
			present = true
			enabled = (p.Attributes & windows.SE_PRIVILEGE_ENABLED) != 0
			return present, enabled, nil
		}
	}

	return false, false, nil
}
