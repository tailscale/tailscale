// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package sparse

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// punchAt for darwin APFS has a quirk where file punches have to exist on block,
// boundaries.  This implementation of PunchAt will handle rounding up to the closest block.
func punchAt(fd *os.File, off, size int64) error {
	blockSize, err := getBlockSize(fd)
	if err != nil {
		return &fs.PathError{Op: "punchAt", Path: fd.Name(), Err: err}
	}
	off, size, err = alignToBlockSize(off, size, blockSize)
	if err != nil {
		return &fs.PathError{Op: "punchAt", Path: fd.Name(), Err: err}
	}
	fstore := &unix.Fstore_t{
		Offset: off,
		Length: size,
	}
	err = unix.FcntlFstore(fd.Fd(), unix.F_PUNCHHOLE, fstore)
	if err != nil {
		return &fs.PathError{Op: "punchAt", Path: fd.Name(), Err: err}
	}
	return nil
}

func getBlockSize(f *os.File) (int64, error) {
	var statfs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &statfs); err != nil {
		return 0, err
	}
	return int64(statfs.Bsize), nil
}

func alignToBlockSize(off, size, blockSize int64) (int64, int64, error) {
	if blockSize <= 0 {
		return 0, 0, errors.New("block size too small")
	}

	// Align the offset up to the nearest block boundary
	alignedOffset := ((off + blockSize - 1) / blockSize) * blockSize

	// Adjust the length to maintain full coverage
	adjustment := alignedOffset - off
	alignedLength := size - adjustment
	if alignedLength < 0 {
		alignedLength = 0
	}
	// Round length up to the nearest multiple of blockSize
	alignedLength = ((alignedLength + blockSize - 1) / blockSize) * blockSize

	return alignedOffset, alignedLength, nil
}
