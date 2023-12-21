// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package webdavfs

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"

	"github.com/tailscale/gowebdav"
)

const (
	// MaxRewindBuffer specifies the size of the rewind buffer for reading
	// from files. For some files, net/http performs content type detection
	// by reading up to the first 512 bytes of a file, then seeking back to the
	// beginning before actually transmitting the file. To support this, we
	// maintain a rewind buffer of 512 bytes.
	MaxRewindBuffer = 512
)

type readOnlyFile struct {
	io.ReadCloser
	name         string
	initialFI    fs.FileInfo
	fi           fs.FileInfo
	client       *gowebdav.Client
	rewindBuffer []byte
	position     int
	mu           sync.RWMutex
}

// Readdir implements webdav.File.
func (f *readOnlyFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, &os.PathError{
		Op:   "readdir",
		Path: f.fi.Name(),
		Err:  errors.New("is a file"), // TODO(oxtoacart): make sure this and below errors match what a regular os.File does
	}
}

// Seek implements webdav.File.
func (f *readOnlyFile) Seek(offset int64, whence int) (int64, error) {
	err := f.statIfNecessary()
	if err != nil {
		return 0, err
	}

	switch whence {
	case io.SeekEnd:
		if offset == 0 {
			// seek to end is usually done to check size, let's play along
			size := f.fi.Size()
			return size, nil
		}
	case io.SeekStart:
		if offset == 0 {
			// this is usually done to start reading after getting size
			if f.position > MaxRewindBuffer {
				return 0, errors.New("attempted seek after having read past rewind buffer")
			}
			f.position = 0
			return 0, nil
		} else if f.position == 0 {
			// this is usually done to perform a range request to skip the head of the file
			f.position = int(offset)
			return offset, nil
		}
	}

	// unknown seek scenario, error out
	return 0, &os.PathError{
		Op:   "seek",
		Path: f.fi.Name(),
		Err:  errors.New("seek not supported"),
	}
}

// Stat implements webdav.File, returning either the FileInfo with which this
// file was initialized, or the more recently fetched FileInfo if available.
func (f *readOnlyFile) Stat() (fs.FileInfo, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.fi != nil {
		return f.fi, nil
	}
	return f.initialFI, nil
}

// Read implements webdav.File.
func (f *readOnlyFile) Read(p []byte) (int, error) {
	err := f.initReaderIfNecessary()
	if err != nil {
		return 0, err
	}

	amountToReadFromBuffer := len(f.rewindBuffer) - f.position
	if amountToReadFromBuffer > 0 {
		n := copy(p, f.rewindBuffer)
		f.position += n
		return n, nil
	}

	n, err := f.ReadCloser.Read(p)
	if n > 0 && f.position < MaxRewindBuffer {
		amountToReadIntoBuffer := MaxRewindBuffer - f.position
		if amountToReadIntoBuffer > n {
			amountToReadIntoBuffer = n
		}
		f.rewindBuffer = append(f.rewindBuffer, p[:amountToReadIntoBuffer]...)
	}

	f.position += n
	return n, err
}

// Write implements webdav.File.
func (f *readOnlyFile) Write(p []byte) (int, error) {
	return 0, &os.PathError{
		Op:   "write",
		Path: f.fi.Name(),
		Err:  errors.New("read-only"),
	}
}

// Close implements webdav.File.
func (f *readOnlyFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ReadCloser == nil {
		return nil
	}
	return f.ReadCloser.Close()
}

// statIfNecessary lazily initializes the FileInfo, bypassing the stat cache to
// make sure we have fresh info before trying to read the file.
func (f *readOnlyFile) statIfNecessary() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.fi == nil {
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()

		var err error
		f.fi, err = f.client.Stat(ctxWithTimeout, f.name)
		if err != nil {
			return translateWebDAVError(err)
		}
	}

	return nil
}

// initReaderIfNecessary initializes the Reader if it hasn't been opened yet. We
// do this lazily because github.com/tailscale/xnet/webdav often opens files in
// read-only mode without ever actually reading from them, so we can improve
// performance by avoiding the round-trip to the server.
func (f *readOnlyFile) initReaderIfNecessary() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ReadCloser == nil {
		var err error
		f.ReadCloser, err = f.client.ReadStreamOffset(context.Background(), f.name, f.position)
		if err != nil {
			return translateWebDAVError(err)
		}
	}

	return nil
}
