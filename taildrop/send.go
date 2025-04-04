// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tstime"
	"tailscale.com/version/distro"
)

type incomingFileKey struct {
	id   ClientID
	name string // e.g., "foo.jpeg"
}

type incomingFile struct {
	clock tstime.DefaultClock

	started        time.Time
	size           int64     // or -1 if unknown; never 0
	w              io.Writer // underlying writer
	sendFileNotify func()    // called when done
	partialPath    string    // non-empty in direct mode
	finalPath      string    // not used in direct mode

	mu         sync.Mutex
	copied     int64
	done       bool
	lastNotify time.Time
}

func (f *incomingFile) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)

	var needNotify bool
	defer func() {
		if needNotify {
			f.sendFileNotify()
		}
	}()
	if n > 0 {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.copied += int64(n)
		now := f.clock.Now()
		if f.lastNotify.IsZero() || now.Sub(f.lastNotify) > time.Second {
			f.lastNotify = now
			needNotify = true
		}
	}
	return n, err
}

// PutFile stores a file into [Manager.Dir] from a given client id.
// The baseName must be a base filename without any slashes.
// The length is the expected length of content to read from r,
// it may be negative to indicate that it is unknown.
// It returns the length of the entire file.
//
// If there is a failure reading from r, then the partial file is not deleted
// for some period of time. The [Manager.PartialFiles] and [Manager.HashPartialFile]
// methods may be used to list all partial files and to compute the hash for a
// specific partial file. This allows the client to determine whether to resume
// a partial file. While resuming, PutFile may be called again with a non-zero
// offset to specify where to resume receiving data at.
func (m *Manager) PutFile(id ClientID, baseName string, r io.Reader, offset, length int64) (int64, error) {
	switch {
	case m == nil || m.opts.Dir == "":
		return 0, ErrNoTaildrop
	case !envknob.CanTaildrop():
		return 0, ErrNoTaildrop
	case distro.Get() == distro.Unraid && !m.opts.DirectFileMode:
		return 0, ErrNotAccessible
	}
	// Determine if we are in SAF mode.
	safMode := m.opts.DirectFileMode && strings.HasPrefix(m.opts.Dir, "content://")
	var dstPath string
	var err error

	if !safMode {
		// Non-SAF mode: build destination path normally.
		dstPath, err = joinDir(m.opts.Dir, baseName)
		if err != nil {
			return 0, err
		}
	} else {
		// In SAF mode, we simply use the baseName as the destination "path"
		// (the actual directory is managed by SAF).
		dstPath = baseName
	}

	redactAndLogError := func(action string, err error) error {
		err = redactError(err)
		m.opts.Logf("put %v error: %v", action, err)
		return err
	}

	// Check whether there is an in-progress transfer for the file.
	partialKey := incomingFileKey{id, baseName}
	inFile, loaded := m.incomingFiles.LoadOrInit(partialKey, func() *incomingFile {
		inFile := &incomingFile{
			clock:          m.opts.Clock,
			started:        m.opts.Clock.Now(),
			size:           length,
			sendFileNotify: m.opts.SendFileNotify,
		}
		if !safMode {
			// In SAF mode, we'll later assign a valid SAF URI to inFile.partialPath.
			inFile.partialPath = dstPath + id.partialSuffix()
			inFile.finalPath = dstPath
		}
		return inFile
	})
	if loaded {
		return 0, ErrFileExists
	}
	defer m.incomingFiles.Delete(partialKey)
	m.deleter.Remove(filepath.Base(dstPath)) // avoid deletion during transfer

	var f *os.File
	var partialPath string
	if safMode {
		if m.fileOps == nil {
			return 0, redactAndLogError("Create (SAF)", fmt.Errorf("missing FileOps"))
		}
		// SAF mode: get file descriptor and initial URI from fileOps.
		fd := m.fileOps.OpenFileDescriptor(baseName)
		uri := m.fileOps.OpenFileURI(baseName)
		if fd < 0 || uri == "" {
			return 0, redactAndLogError("Create (SAF)", fmt.Errorf("failed to open file for writing via SAF"))
		}
		f = os.NewFile(uintptr(fd), baseName)
		partialPath = uri
		inFile.partialPath = partialPath
		inFile.finalPath = baseName
	} else {
		// Traditional filesystem mode.
		partialPath = dstPath + id.partialSuffix()
		f, err = os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return 0, redactAndLogError("Create", err)
		}
	}
	defer func() {
		f.Close() // best-effort to cleanup dangling file handles
		if err != nil {
			m.deleter.Insert(filepath.Base(partialPath))
		}
	}()
	inFile.w = f

	// Record that we have started to receive at least one file.
	// This is used by the deleter upon a cold-start to scan the directory
	// for any files that need to be deleted.
	if m.opts.State != nil {
		if b, _ := m.opts.State.ReadState(ipn.TaildropReceivedKey); len(b) == 0 {
			if err := m.opts.State.WriteState(ipn.TaildropReceivedKey, []byte{1}); err != nil {
				m.opts.Logf("WriteState error: %v", err) // non-fatal error
			}
		}
	}

	// A positive offset implies that we are resuming an existing file.
	// Seek to the appropriate offset and truncate the file.
	if offset != 0 {
		currLength, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, redactAndLogError("Seek", err)
		}
		if offset < 0 || offset > currLength {
			return 0, redactAndLogError("Seek", err)
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return 0, redactAndLogError("Seek", err)
		}
		if err := f.Truncate(offset); err != nil {
			return 0, redactAndLogError("Truncate", err)
		}
	}

	// Copy the contents of the file.
	copyLength, err := io.Copy(inFile, r)
	if err != nil {
		return 0, redactAndLogError("Copy", err)
	}
	if length >= 0 && copyLength != length {
		return 0, redactAndLogError("Copy", errors.New("copied an unexpected number of bytes"))
	}
	if err := f.Close(); err != nil {
		return 0, redactAndLogError("Close", err)
	}
	fileLength := offset + copyLength

	inFile.mu.Lock()
	inFile.done = true
	inFile.mu.Unlock()

	// File has been successfully received, rename the partial file
	// to the final destination filename. If a file of that name already exists,
	// then try multiple times with variations of the filename.
	if safMode {
		// SAF mode: Use a retry loop similar to non‑SAF mode.
		maxRetries := 10
		finalName := baseName
		var newURI string
		for i := 0; i < maxRetries; i++ {
			newURI, err = m.fileOps.RenamePartialFile(partialPath, m.opts.Dir, finalName)
			if err != nil {
				return 0, redactAndLogError("Rename", err)
			}
			// If the returned URI is non-empty and differs from our candidate, assume it’s been adjusted.
			if newURI != "" && newURI != finalName {
				finalName = newURI // update candidate name if necessary
				break
			}
			// If newURI is empty or identical, try generating a new filename.
			finalName = NextFilename(finalName)
		}
		if newURI == "" {
			return 0, redactAndLogError("Rename", fmt.Errorf("failed to finalize SAF file after retries"))
		}
		inFile.finalPath = finalName
	} else {
		computePartialSum := sync.OnceValues(func() ([sha256.Size]byte, error) {
			return sha256File(partialPath)
		})
		maxRetries := 10
		for ; maxRetries > 0; maxRetries-- {

			// Atomically rename the partial file as the destination file if it doesn't exist.
			// Otherwise, it returns the length of the current destination file.
			// The operation is atomic.
			dstLength, err := func() (int64, error) {
				m.renameMu.Lock()
				defer m.renameMu.Unlock()
				switch fi, err := os.Stat(dstPath); {
				case os.IsNotExist(err):
					dstPath, err = joinDir(m.opts.Dir, baseName)
					if err != nil {
						return 0, err
					}
					return -1, os.Rename(partialPath, dstPath)
				case err != nil:
					return -1, err
				default:
					return fi.Size(), nil
				}
			}()
			if err != nil {
				return 0, redactAndLogError("Rename", err)
			}
			if dstLength < 0 {
				break // we successfully renamed; so stop
			}
			// Avoid the final rename if a destination file has the same contents.
			if dstLength == fileLength {
				partialSum, err := computePartialSum()
				if err != nil {
					return 0, redactAndLogError("Rename", err)
				}
				dstSum, err := sha256File(dstPath)
				if err != nil {
					return 0, redactAndLogError("Rename", err)
				}
				if dstSum == partialSum {
					if err := os.Remove(partialPath); err != nil {
						return 0, redactAndLogError("Remove", err)
					}
					break // we successfully found a content match; so stop
				}
			}
			// Choose a new destination filename and try again.
			dstPath = NextFilename(dstPath)
			inFile.finalPath = dstPath
		}
		if maxRetries <= 0 {
			return 0, fmt.Errorf("too many retries trying to rename partial file")
		}
	}
	m.totalReceived.Add(1)
	m.opts.SendFileNotify()
	return fileLength, nil
}

func sha256File(file string) (out [sha256.Size]byte, err error) {
	h := sha256.New()
	f, err := os.Open(file)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	return [sha256.Size]byte(h.Sum(nil)), nil
}
