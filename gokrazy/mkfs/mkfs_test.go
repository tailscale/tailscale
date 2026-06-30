// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package mkfs

import (
	"bytes"
	"testing"

	"github.com/diskfs/go-diskfs/filesystem/ext4"
)

// fakeWriterAt records every WriteAt to a single contiguous backing
// buffer (so tests can inspect what flushTo produced) and counts the
// calls so we can assert the chunked flush issues a predictable
// handful of big sequential writes.
type fakeWriterAt struct {
	buf   []byte
	calls int
	sizes []int
}

func (w *fakeWriterAt) WriteAt(p []byte, off int64) (int, error) {
	w.calls++
	w.sizes = append(w.sizes, len(p))
	if int(off)+len(p) > len(w.buf) {
		w.buf = append(w.buf, make([]byte, int(off)+len(p)-len(w.buf))...)
	}
	return copy(w.buf[off:], p), nil
}

// TestMemBackendSparseAlloc exercises ext4.Create against an in-memory
// memBackend sized like a typical /perm partition and confirms that
// the page allocator stays small. ext4.Create issues writes for tens
// to hundreds of MiB of zero-initialized inode table and journal; we
// rely on memBackend.WriteAt suppressing those zero writes so that
// the eventual flush to the (slow) SD card stays under a few MiB.
//
// The assertion is intentionally loose — we only catch regressions
// that bloat by an order of magnitude, not bookkeeping changes.
func TestMemBackendSparseAlloc(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sizeBytes   int64
		maxPagesKiB int64
	}{
		// ~96 MiB matches our tsapp pi/vm builds with
		// target_storage_bytes=1258299392.
		{"96MiB", 96 * 1024 * 1024, 256},
		// 2 GiB is the size the user complained about in the
		// flash-appliance progress meter: ext4.Create wrote ~131
		// MiB before suppression.
		{"2GiB", 2 * 1024 * 1024 * 1024, 1024},
		// 32 GiB simulates a full-size SD card. ext4.Create would
		// write a few hundred MiB of zeros for the inode table; we
		// must still stay tiny.
		{"32GiB", 32 * 1024 * 1024 * 1024, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := newMemBackend(tc.sizeBytes)
			_, err := ext4.Create(mem, tc.sizeBytes, 0, sectorSize, &ext4.Params{
				VolumeName:      "PERM",
				SectorsPerBlock: 8,
				Features: []ext4.FeatureOpt{
					ext4.WithFeatureReservedGDTBlocksForExpansion(false),
				},
			})
			if err != nil {
				t.Fatalf("ext4.Create: %v", err)
			}
			pageBytes := int64(len(mem.pages)) * memPageSize
			t.Logf("%s filesystem: %d allocated pages (%d KiB)",
				tc.name, len(mem.pages), pageBytes/1024)
			if pageBytes/1024 > tc.maxPagesKiB {
				t.Errorf("allocated %d KiB; want < %d KiB", pageBytes/1024, tc.maxPagesKiB)
			}
		})
	}
}

// TestFlushToDirtyOnly exercises memBackend.flushTo against a fake
// io.WriterAt: it must issue only one WriteAt per maximal run of
// allocated (non-zero) pages — never anything for the gaps in between
// — and the bytes at each destination offset must match what was
// originally written.
func TestFlushToDirtyOnly(t *testing.T) {
	const size = 40 * 1024 * 1024
	m := newMemBackend(size)

	// Two contiguous runs separated by a large all-zero gap. The
	// flush should issue exactly two WriteAt calls (one per run),
	// and never touch the gap between them.
	page := func(b byte) []byte {
		p := make([]byte, memPageSize)
		p[0] = b
		return p
	}
	// Run 1: 2 consecutive pages at offset 0.
	if _, err := m.WriteAt(page(0x11), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if _, err := m.WriteAt(page(0x22), memPageSize); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	// Run 2: 1 page at the end of the region.
	if _, err := m.WriteAt(page(0x33), size-memPageSize); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	const baseOffset int64 = 1 << 20
	fw := &fakeWriterAt{}
	if err := m.flushTo(fw, baseOffset); err != nil {
		t.Fatalf("flushTo: %v", err)
	}

	if fw.calls != 2 {
		t.Errorf("WriteAt calls=%d; want 2 (one per dirty run), sizes=%v", fw.calls, fw.sizes)
	}
	if got, want := fw.sizes[0], 2*memPageSize; got != want {
		t.Errorf("first run size=%d; want %d (2 contiguous pages)", got, want)
	}
	if got, want := fw.sizes[1], memPageSize; got != want {
		t.Errorf("second run size=%d; want %d (1 page)", got, want)
	}

	// Page contents at the right absolute offsets.
	if fw.buf[baseOffset+0] != 0x11 {
		t.Errorf("page 0 marker = %#x; want 0x11", fw.buf[baseOffset+0])
	}
	if fw.buf[baseOffset+memPageSize] != 0x22 {
		t.Errorf("page 1 marker = %#x; want 0x22", fw.buf[baseOffset+memPageSize])
	}
	if fw.buf[baseOffset+size-memPageSize] != 0x33 {
		t.Errorf("last page marker = %#x; want 0x33", fw.buf[baseOffset+size-memPageSize])
	}
	// The gap pages between run 1 and run 2 must not have been touched
	// at all in the fake's backing buffer (it lazily grows on WriteAt;
	// untouched bytes stay zero).
	for _, off := range []int64{2 * memPageSize, 8 * 1024 * 1024, 20 * 1024 * 1024} {
		if !bytes.Equal(fw.buf[baseOffset+off:baseOffset+off+memPageSize], make([]byte, memPageSize)) {
			t.Errorf("flushTo touched an unallocated gap at offset %d", off)
		}
	}
}

// TestMemBackendZeroSuppressed asserts that a write whose data is all
// zero does not allocate a page when the destination page is absent —
// the core invariant that makes TestMemBackendSparseAlloc pass — and
// that writes touching multiple pages allocate per-page based on
// whether each page's slice has any non-zero byte.
func TestMemBackendZeroSuppressed(t *testing.T) {
	m := newMemBackend(1 << 20)

	// All-zero write spanning 2 pages: nothing allocated.
	zero := make([]byte, 8192)
	if _, err := m.WriteAt(zero, 4096); err != nil {
		t.Fatalf("WriteAt zero: %v", err)
	}
	if got := len(m.pages); got != 0 {
		t.Errorf("after %d-byte zero write: %d pages, want 0", len(zero), got)
	}

	// Non-zero byte in page 0 only: page 0 allocated; page 1 stays
	// zero-suppressed.
	mixed := make([]byte, 8192)
	mixed[100] = 1
	if _, err := m.WriteAt(mixed, 0); err != nil {
		t.Fatalf("WriteAt mixed: %v", err)
	}
	if got := len(m.pages); got != 1 {
		t.Errorf("after write with non-zero only in page 0: %d pages, want 1", got)
	}

	// Non-zero bytes in both pages: both allocated.
	m = newMemBackend(1 << 20)
	mixed[5000] = 1 // also non-zero in page 1
	if _, err := m.WriteAt(mixed, 0); err != nil {
		t.Fatalf("WriteAt mixed-both: %v", err)
	}
	if got := len(m.pages); got != 2 {
		t.Errorf("after write with non-zero in pages 0 and 1: %d pages, want 2", got)
	}
}
