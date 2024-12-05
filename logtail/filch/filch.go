// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package filch is a file system queue that pilfers your stderr.
// (A FILe CHannel that filches.)
package filch

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

var stderrFD = 2 // a variable for testing

const defaultMaxFileSize = 50 << 20

type Options struct {
	ReplaceStderr bool // dup over fd 2 so everything written to stderr comes here
	MaxFileSize   int
}

// A Filch uses two alternating files as a simplistic ring buffer.
type Filch struct {
	OrigStderr *os.File

	mu        sync.Mutex
	cur       *os.File
	alt       *os.File
	altscan   *bufio.Scanner
	recovered int64

	maxFileSize  int64
	writeCounter int

	// buf is an initial buffer for altscan.
	// As of August 2021, 99.96% of all log lines
	// are below 4096 bytes in length.
	// Since this cutoff is arbitrary, instead of using 4096,
	// we subtract off the size of the rest of the struct
	// so that the whole struct takes 4096 bytes
	// (less on 32 bit platforms).
	// This reduces allocation waste.
	buf [4096 - 64]byte
}

// TryReadline implements the logtail.Buffer interface.
func (f *Filch) TryReadLine() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.altscan != nil {
		if b, err := f.scan(); b != nil || err != nil {
			return b, err
		}
	}

	f.cur, f.alt = f.alt, f.cur
	if f.OrigStderr != nil {
		if err := dup2Stderr(f.cur); err != nil {
			return nil, err
		}
	}
	if _, err := f.alt.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	f.altscan = bufio.NewScanner(f.alt)
	f.altscan.Buffer(f.buf[:], bufio.MaxScanTokenSize)
	f.altscan.Split(splitLines)
	return f.scan()
}

func (f *Filch) scan() ([]byte, error) {
	if f.altscan.Scan() {
		return f.altscan.Bytes(), nil
	}
	err := f.altscan.Err()
	err2 := f.alt.Truncate(0)
	_, err3 := f.alt.Seek(0, io.SeekStart)
	f.altscan = nil
	if err != nil {
		return nil, err
	}
	if err2 != nil {
		return nil, err2
	}
	if err3 != nil {
		return nil, err3
	}
	return nil, nil
}

// Write implements the logtail.Buffer interface.
func (f *Filch) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeCounter == 100 {
		// Check the file size every 100 writes.
		f.writeCounter = 0
		fi, err := f.cur.Stat()
		if err != nil {
			return 0, err
		}
		if fi.Size() >= f.maxFileSize {
			// This most likely means we are not draining.
			// To limit the amount of space we use, throw away the old logs.
			if err := moveContents(f.alt, f.cur); err != nil {
				return 0, err
			}
		}
	}
	f.writeCounter++

	if len(b) == 0 || b[len(b)-1] != '\n' {
		bnl := make([]byte, len(b)+1)
		copy(bnl, b)
		bnl[len(bnl)-1] = '\n'
		return f.cur.Write(bnl)
	}
	return f.cur.Write(b)
}

// Close closes the Filch, releasing all os resources.
func (f *Filch) Close() (err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.OrigStderr != nil {
		if err2 := unsaveStderr(f.OrigStderr); err == nil {
			err = err2
		}
		f.OrigStderr = nil
	}

	if err2 := f.cur.Close(); err == nil {
		err = err2
	}
	if err2 := f.alt.Close(); err == nil {
		err = err2
	}

	return err
}

// New creates a new filch around two log files, each starting with filePrefix.
func New(filePrefix string, opts Options) (f *Filch, err error) {
	var f1, f2 *os.File
	defer func() {
		if err != nil {
			if f1 != nil {
				f1.Close()
			}
			if f2 != nil {
				f2.Close()
			}
			err = fmt.Errorf("filch: %s", err)
		}
	}()

	path1 := filePrefix + ".log1.txt"
	path2 := filePrefix + ".log2.txt"

	f1, err = os.OpenFile(path1, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f2, err = os.OpenFile(path2, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	fi1, err := f1.Stat()
	if err != nil {
		return nil, err
	}
	fi2, err := f2.Stat()
	if err != nil {
		return nil, err
	}

	mfs := defaultMaxFileSize
	if opts.MaxFileSize > 0 {
		mfs = opts.MaxFileSize
	}
	f = &Filch{
		OrigStderr:  os.Stderr, // temporary, for past logs recovery
		maxFileSize: int64(mfs),
	}

	// Neither, either, or both files may exist and contain logs from
	// the last time the process ran. The three cases are:
	//
	//	- neither: all logs were read out and files were truncated
	//	- either: logs were being written into one of the files
	//	- both: the files were swapped and were starting to be
	//		read out, while new logs streamed into the other
	//		file, but the read out did not complete
	if n := fi1.Size() + fi2.Size(); n > 0 {
		f.recovered = n
	}
	switch {
	case fi1.Size() > 0 && fi2.Size() == 0:
		f.cur, f.alt = f2, f1
	case fi2.Size() > 0 && fi1.Size() == 0:
		f.cur, f.alt = f1, f2
	case fi1.Size() > 0 && fi2.Size() > 0: // both
		// We need to pick one of the files to be the elder,
		// which we do using the mtime.
		var older, newer *os.File
		if fi1.ModTime().Before(fi2.ModTime()) {
			older, newer = f1, f2
		} else {
			older, newer = f2, f1
		}
		if err := moveContents(older, newer); err != nil {
			fmt.Fprintf(f.OrigStderr, "filch: recover move failed: %v\n", err)
			fmt.Fprintf(older, "filch: recover move failed: %v\n", err)
		}
		f.cur, f.alt = newer, older
	default:
		f.cur, f.alt = f1, f2 // does not matter
	}
	if f.recovered > 0 {
		f.altscan = bufio.NewScanner(f.alt)
		f.altscan.Buffer(f.buf[:], bufio.MaxScanTokenSize)
		f.altscan.Split(splitLines)
	}

	f.OrigStderr = nil
	if opts.ReplaceStderr {
		f.OrigStderr, err = saveStderr()
		if err != nil {
			return nil, err
		}
		if err := dup2Stderr(f.cur); err != nil {
			return nil, err
		}
	}

	return f, nil
}

func moveContents(dst, src *os.File) (err error) {
	defer func() {
		_, err2 := src.Seek(0, io.SeekStart)
		err3 := src.Truncate(0)
		_, err4 := dst.Seek(0, io.SeekStart)
		if err == nil {
			err = err2
		}
		if err == nil {
			err = err3
		}
		if err == nil {
			err = err4
		}
	}()
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return nil
}

func splitLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[0 : i+1], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
