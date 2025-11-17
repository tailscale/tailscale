// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"reflect"
	"testing"
	"unsafe"
)

//lint:file-ignore U1000 Fields are unused but necessary for tests.

const (
	localSystemSID = "S-1-5-18"
	networkSID     = "S-1-5-2"
)

func TestLookupPseudoUser(t *testing.T) {
	localSystem, err := LookupPseudoUser(localSystemSID)
	if err != nil {
		t.Errorf("LookupPseudoUser(%q) error: %v", localSystemSID, err)
	}
	if localSystem.Gid != localSystemSID {
		t.Errorf("incorrect Gid, got %q, want %q", localSystem.Gid, localSystemSID)
	}
	t.Logf("localSystem: %v", localSystem)

	// networkSID is a built-in known group but not a pseudo-user.
	_, err = LookupPseudoUser(networkSID)
	if err == nil {
		t.Errorf("LookupPseudoUser(%q) unexpectedly succeeded", networkSID)
	}
}

type testType interface {
	byte | uint16 | uint32 | uint64
}

type noPointers[T testType] struct {
	foo byte
	bar T
	baz bool
}

type hasPointer struct {
	foo byte
	bar uint32
	s1  *struct{}
	baz byte
}

func checkContiguousBuffer[T any, BU BufUnit](t *testing.T, extra []BU, pt *T, ptLen uint32, slcs [][]BU) {
	szBU := int(unsafe.Sizeof(BU(0)))
	expectedAlign := max(reflect.TypeFor[T]().Align(), szBU)
	// Check that pointer is aligned
	if rem := uintptr(unsafe.Pointer(pt)) % uintptr(expectedAlign); rem != 0 {
		t.Errorf("pointer alignment got %d, want 0", rem)
	}
	// Check that alloc length is aligned
	if rem := int(ptLen) % expectedAlign; rem != 0 {
		t.Errorf("allocation length alignment got %d, want 0", rem)
	}
	expectedLen := int(unsafe.Sizeof(*pt))
	expectedLen = alignUp(expectedLen, szBU)
	expectedLen += len(extra) * szBU
	expectedLen = alignUp(expectedLen, expectedAlign)
	if gotLen := int(ptLen); gotLen != expectedLen {
		t.Errorf("allocation length got %d, want %d", gotLen, expectedLen)
	}
	if ln := len(slcs); ln != 1 {
		t.Errorf("len(slcs) got %d, want 1", ln)
	}
	if len(extra) == 0 && slcs[0] != nil {
		t.Error("slcs[0] got non-nil, want nil")
	}
	if len(extra) != len(slcs[0]) {
		t.Errorf("len(slcs[0]) got %d, want %d", len(slcs[0]), len(extra))
	} else if rem := uintptr(unsafe.Pointer(unsafe.SliceData(slcs[0]))) % uintptr(szBU); rem != 0 {
		t.Errorf("additional data alignment got %d, want 0", rem)
	}
}

func TestAllocateContiguousBuffer(t *testing.T) {
	t.Run("NoValues", testNoValues)
	t.Run("NoPointers", testNoPointers)
	t.Run("HasPointer", testHasPointer)
}

func testNoValues(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic but didn't get one")
		}
	}()

	AllocateContiguousBuffer[hasPointer, byte]()
}

const maxTestBufLen = 8

func testNoPointers(t *testing.T) {
	buf8 := make([]byte, maxTestBufLen)
	buf16 := make([]uint16, maxTestBufLen)
	for i := range maxTestBufLen {
		s8, sl, slcs8 := AllocateContiguousBuffer[noPointers[byte]](buf8[:i])
		checkContiguousBuffer(t, buf8[:i], s8, sl, slcs8)
		s16, sl, slcs8 := AllocateContiguousBuffer[noPointers[uint16]](buf8[:i])
		checkContiguousBuffer(t, buf8[:i], s16, sl, slcs8)
		s32, sl, slcs8 := AllocateContiguousBuffer[noPointers[uint32]](buf8[:i])
		checkContiguousBuffer(t, buf8[:i], s32, sl, slcs8)
		s64, sl, slcs8 := AllocateContiguousBuffer[noPointers[uint64]](buf8[:i])
		checkContiguousBuffer(t, buf8[:i], s64, sl, slcs8)
		s8, sl, slcs16 := AllocateContiguousBuffer[noPointers[byte]](buf16[:i])
		checkContiguousBuffer(t, buf16[:i], s8, sl, slcs16)
		s16, sl, slcs16 = AllocateContiguousBuffer[noPointers[uint16]](buf16[:i])
		checkContiguousBuffer(t, buf16[:i], s16, sl, slcs16)
		s32, sl, slcs16 = AllocateContiguousBuffer[noPointers[uint32]](buf16[:i])
		checkContiguousBuffer(t, buf16[:i], s32, sl, slcs16)
		s64, sl, slcs16 = AllocateContiguousBuffer[noPointers[uint64]](buf16[:i])
		checkContiguousBuffer(t, buf16[:i], s64, sl, slcs16)
	}
}

func testHasPointer(t *testing.T) {
	buf8 := make([]byte, maxTestBufLen)
	buf16 := make([]uint16, maxTestBufLen)
	for i := range maxTestBufLen {
		s, sl, slcs8 := AllocateContiguousBuffer[hasPointer](buf8[:i])
		checkContiguousBuffer(t, buf8[:i], s, sl, slcs8)
		s, sl, slcs16 := AllocateContiguousBuffer[hasPointer](buf16[:i])
		checkContiguousBuffer(t, buf16[:i], s, sl, slcs16)
	}
}
