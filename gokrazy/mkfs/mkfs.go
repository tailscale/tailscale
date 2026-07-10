// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package mkfs creates the writable ext4 /perm filesystem inside a
// gokrazy disk image or block device, at the offset and length
// determined by the gokrazy partition layout.
//
// Used by gokrazy/build.go when producing a "--full" disk image and by
// "tailscale configure flash-appliance" when flashing an image to an
// SD card, so the appliance has a working /perm on first boot without
// requiring users to install mkfs.ext4 (e.g. e2fsprogs on macOS).
package mkfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/bradfitz/monogok/disklayout"
	"github.com/diskfs/go-diskfs/backend"
	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"tailscale.com/util/progresstracking"
)

// gptSecondaryReservedSectors is the number of 512-byte sectors that
// monogok's GPT writer reserves at the end of the disk for the
// secondary GPT (1 header sector + 32 partition-entry sectors). The
// perm partition entry written by disklayout.WriteGPT is this many
// sectors shorter than [disklayout.PermSize], so the ext4 filesystem
// we create must shrink by the same amount to fit within the partition
// the kernel sees.
const gptSecondaryReservedSectors = 34

const sectorSize = 512

// PermFile is a file to include in the /perm partition.
type PermFile struct {
	Path    string // path within the filesystem, e.g. "breakglass.authorized_keys"
	Content []byte
}

// Perm creates an ext4 filesystem with volume label "PERM" inside the
// gokrazy /perm partition of f. devsizeBytes is the total disk size
// that the gokrazy GPT in f was written for; the partition layout is
// derived from it via [disklayout].
//
// If files is non-empty, the listed files are written into the
// filesystem before flushing to disk.
//
// To avoid issuing ext4.Create's hundreds of small scattered writes
// against slow storage one syscall at a time, the filesystem is first
// built in an in-memory sparse buffer and then only the genuinely
// non-zero metadata pages are flushed to f, coalesced into the
// fewest possible contiguous writes. ext4's initial superblock,
// group descriptors, bitmaps, root inode, etc. land at the same
// per-group byte offsets whether the destination had old ext4
// metadata or zeros there, so a fresh ext4 always overwrites stale
// metadata in place; data-area bytes that were never written are
// not read by the kernel until they're allocated.
//
// f must be open read/write, and on macOS should be the buffered
// /dev/diskN device rather than the raw /dev/rdiskN alias.
func Perm(f *os.File, devsizeBytes int64, files ...PermFile) error {
	permStart := int64(disklayout.PermStartLBA(disklayout.DefaultBootPartitionStartLBA)) * sectorSize
	permSize := int64(disklayout.PermSize(disklayout.DefaultBootPartitionStartLBA, uint64(devsizeBytes))-gptSecondaryReservedSectors) * sectorSize

	fmt.Fprintf(os.Stderr, "Formatting /perm as ext4 (PERM): %s filesystem\n", humanBytes(permSize))

	mem := newMemBackend(permSize)
	fsys, err := ext4.Create(mem, permSize, 0, sectorSize, &ext4.Params{
		VolumeName: "PERM",
		// Force 4 KiB blocks. go-diskfs v1.9.3 otherwise defaults to 1
		// KiB blocks regardless of filesystem size, which makes a 128
		// MiB journal need ~131k blocks — past the 65535-blocks-per-
		// extent limit. 4 KiB blocks keep a typical journal in a
		// single extent. (Fixed upstream after v1.9.3.)
		SectorsPerBlock: 8,
		// Disable resize_inode. go-diskfs v1.9.3 only implements it
		// for 1 KiB block filesystems; for our 4 KiB blocks +
		// ~96 MiB perm, initResizeInode fails with "no backup groups
		// available". Matches go-diskfs's own tests for non-1 KiB
		// block sizes.
		Features: []ext4.FeatureOpt{
			ext4.WithFeatureReservedGDTBlocksForExpansion(false),
		},
	})
	if err != nil {
		return fmt.Errorf("ext4.Create: %w", err)
	}
	for _, pf := range files {
		w, err := fsys.OpenFile("/"+pf.Path, os.O_CREATE|os.O_RDWR)
		if err != nil {
			return fmt.Errorf("create %s in /perm: %w", pf.Path, err)
		}
		if _, err := w.Write(pf.Content); err != nil {
			return fmt.Errorf("write %s in /perm: %w", pf.Path, err)
		}
	}
	return mem.flushTo(f, permStart)
}

// memPageSize is the granularity of memBackend's sparse allocation.
// 4 KiB matches the ext4 block size we use, so most of ext4.Create's
// writes touch exactly one page.
const memPageSize = 4096

// memBackend is a sparse in-memory implementation of go-diskfs's
// [backend.Storage]. It only allocates a [memPageSize]-byte chunk for
// each page that ext4.Create actually touches; unwritten regions cost
// only a map entry's worth of overhead and read back as zeros. The
// caller flushes the allocated pages to the destination in contiguous
// runs via [memBackend.flushTo].
type memBackend struct {
	size  int64            // logical size of the virtual device
	pages map[int64][]byte // page index → memPageSize bytes
	off   int64            // current offset for io.Reader / io.Seeker compatibility
}

func newMemBackend(size int64) *memBackend {
	return &memBackend{
		size:  size,
		pages: make(map[int64][]byte),
	}
}

// ReadAt implements [io.ReaderAt]. Bytes within pages that were never
// written read as zero.
func (m *memBackend) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= m.size {
		return 0, io.EOF
	}
	if max := m.size - off; int64(len(p)) > max {
		p = p[:max]
	}
	// Default everything to zero; allocated pages overwrite below.
	clear(p)
	total := 0
	for total < len(p) {
		absOff := off + int64(total)
		page := absOff / memPageSize
		within := int(absOff % memPageSize)
		room := min(memPageSize-within, len(p)-total)
		if chunk, ok := m.pages[page]; ok {
			copy(p[total:total+room], chunk[within:within+room])
		}
		total += room
	}
	if int64(total) < int64(len(p)) {
		return total, io.EOF
	}
	return total, nil
}

// WriteAt implements [io.WriterAt]. Pages are allocated on first
// touch, except that writes whose data is entirely zero do NOT
// allocate (or modify) any page: the caller's destination is assumed
// to already have zeros where we never write. ext4.Create writes
// tens-to-hundreds of MiB of zeros to initialize the inode table and
// journal; suppressing those allocations is what keeps memory and SD
// card writes proportional to the *real* metadata rather than the
// filesystem size.
//
// CAVEAT: if the destination has stale non-zero data in those regions
// (e.g. an SD card previously formatted with a different filesystem),
// that data is left in place. For a fresh card this is fine; for
// re-flashed cards the perm region's old data could confuse ext4's
// recovery on first mount. Callers that re-flash should discard the
// perm region first; we don't do that here.
func (m *memBackend) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > m.size {
		return 0, fmt.Errorf("write past buffer end: off=%d len=%d size=%d", off, len(p), m.size)
	}
	total := 0
	for total < len(p) {
		absOff := off + int64(total)
		page := absOff / memPageSize
		within := int(absOff % memPageSize)
		room := min(memPageSize-within, len(p)-total)
		chunk, ok := m.pages[page]
		if !ok && isAllZero(p[total:total+room]) {
			// Don't allocate a fresh zero page.
			total += room
			continue
		}
		if !ok {
			chunk = make([]byte, memPageSize)
			m.pages[page] = chunk
		}
		copy(chunk[within:within+room], p[total:total+room])
		total += room
	}
	return total, nil
}

// isAllZero reports whether p is entirely 0x00.
func isAllZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// Read implements [io.Reader].
func (m *memBackend) Read(p []byte) (int, error) {
	n, err := m.ReadAt(p, m.off)
	m.off += int64(n)
	return n, err
}

// Seek implements [io.Seeker].
func (m *memBackend) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		m.off = off
	case io.SeekCurrent:
		m.off += off
	case io.SeekEnd:
		m.off = m.size + off
	default:
		return 0, fmt.Errorf("invalid whence %d", whence)
	}
	return m.off, nil
}

// Close implements [io.Closer].
func (m *memBackend) Close() error { return nil }

// Stat implements [fs.File].
func (m *memBackend) Stat() (fs.FileInfo, error) {
	return memFileInfo{size: m.size}, nil
}

// Sys implements [backend.Storage]; it returns ErrNotSuitable so
// ext4.Create's optional fsync (ext4.go:730) is gracefully skipped.
func (m *memBackend) Sys() (*os.File, error) { return nil, backend.ErrNotSuitable }

// Writable implements [backend.Storage].
func (m *memBackend) Writable() (backend.WritableFile, error) { return m, nil }

// Path implements [backend.Storage].
func (m *memBackend) Path() string { return "" }

type memFileInfo struct{ size int64 }

func (fi memFileInfo) Name() string       { return "mkfs-buffer" }
func (fi memFileInfo) Size() int64        { return fi.size }
func (fi memFileInfo) Mode() fs.FileMode  { return 0o600 }
func (fi memFileInfo) ModTime() time.Time { return time.Time{} }
func (fi memFileInfo) IsDir() bool        { return false }
func (fi memFileInfo) Sys() any           { return nil }

// flushTo writes the allocated (non-zero) pages of m to f at
// baseOffset+pageIndex*memPageSize, coalescing consecutive page
// indices into a single WriteAt so the destination sees the fewest
// possible writes. Pages that ext4.Create only ever wrote zeros into
// were never allocated by WriteAt and are not written here either; the
// destination is assumed to have zeros (or a previous ext4 install's
// metadata in the same locations, which is functionally equivalent
// since fresh ext4 metadata overwrites it in place).
//
// Progress is printed to os.Stderr roughly once per second.
func (m *memBackend) flushTo(f io.WriterAt, baseOffset int64) error {
	if len(m.pages) == 0 {
		return errors.New("BUG: ext4.Create allocated no pages")
	}

	keys := make([]int64, 0, len(m.pages))
	for k := range m.pages {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	totalBytes := int64(len(m.pages)) * memPageSize
	var written atomic.Int64
	stop := startExt4FlushProgress(&written, totalBytes)
	defer stop()

	for i := 0; i < len(keys); {
		runStart := keys[i]
		j := i
		for j < len(keys) && keys[j] == runStart+int64(j-i) {
			j++
		}
		runPages := keys[i:j]
		buf := make([]byte, len(runPages)*memPageSize)
		for k, page := range runPages {
			copy(buf[k*memPageSize:], m.pages[page])
		}
		if _, err := f.WriteAt(buf, baseOffset+runStart*memPageSize); err != nil {
			return fmt.Errorf("flushing perm metadata: %w", err)
		}
		written.Add(int64(len(buf)))
		i = j
	}
	return nil
}

func startExt4FlushProgress(done *atomic.Int64, total int64) func() {
	return progresstracking.Ticker(done.Load, total, func(d, t int64) {
		pct := 0.0
		if t > 0 {
			pct = float64(d) * 100 / float64(t)
		}
		fmt.Fprintf(os.Stderr, "  ext4 perm: %s / %s (%.1f%%)\n",
			humanBytes(d), humanBytes(t), pct)
	})
}

func humanBytes(n int64) string {
	const (
		gb = 1 << 30
		mb = 1 << 20
		kb = 1 << 10
	)
	switch {
	case n >= gb:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
