// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tstime"
	"tailscale.com/version/distro"
)

type incomingFileKey struct {
	id   ClientID
	name string // e.g., "foo.jpeg"
}

type IncomingFile struct {
	clock tstime.DefaultClock

	Name           string // "foo.jpg"
	Started        time.Time
	Size           int64     // or -1 if unknown; never 0
	W              io.Writer // underlying writer
	sendFileNotify func()    // called when done
	PartialPath    string    // non-empty in direct mode

	Mu         sync.Mutex
	Copied     int64
	Done       bool
	lastNotify time.Time
}

// type incomingFile struct {
// 	name        string // "foo.jpg"
// 	started     time.Time
// 	size        int64     // or -1 if unknown; never 0
// 	w           io.Writer // underlying writer
// 	ph          *peerAPIHandler
// 	partialPath string // non-empty in direct mode

// 	mu         sync.Mutex
// 	copied     int64
// 	done       bool
// 	lastNotify time.Time
// }

func (f *IncomingFile) PartialFile() PartialFile {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return PartialFile{
		Name:         f.Name,
		Started:      f.Started,
		DeclaredSize: f.Size,
		Received:     f.Copied,
		PartialPath:  f.PartialPath,
		Done:         f.Done,
	}
}

// PartialFile represents an in-progress file transfer.
type PartialFile struct {
	Name         string    // e.g. "foo.jpg"
	Started      time.Time // time transfer started
	DeclaredSize int64     // or -1 if unknown
	Received     int64     // bytes copied thus far

	// PartialPath is set non-empty in "direct" file mode to the
	// in-progress '*.partial' file's path when the peerapi isn't
	// being used; see LocalBackend.SetDirectFileRoot.
	PartialPath string `json:",omitempty"`

	// Done is set in "direct" mode when the partial file has been
	// closed and is ready for the caller to rename away the
	// ".partial" suffix.
	Done bool `json:",omitempty"`
}

func (f *IncomingFile) Write(p []byte) (n int, err error) {
	n, err = f.W.Write(p)

	var needNotify bool
	defer func() {
		if needNotify {
			f.sendFileNotify()
		}
	}()
	if n > 0 {
		f.Mu.Lock()
		defer f.Mu.Unlock()
		f.Copied += int64(n)
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
	dstPath, err := joinDir(m.opts.Dir, baseName)
	if err != nil {
		return 0, err
	}

	redactAndLogError := func(action string, err error) error {
		err = redactError(err)
		m.opts.Logf("put %v error: %v", action, err)
		return err
	}

	avoidPartialRename := m.opts.DirectFileMode && m.opts.AvoidFinalRename
	if avoidPartialRename {
		// Users using AvoidFinalRename are depending on the exact filename
		// of the partial files. So avoid injecting the id into it.
		id = ""
	}

	// Check whether there is an in-progress transfer for the file.
	partialPath := dstPath + id.partialSuffix()
	inFileKey := incomingFileKey{id, baseName}
	inFile, loaded := m.incomingFiles.LoadOrInit(inFileKey, func() *IncomingFile {
		inFile := &IncomingFile{
			clock:          m.opts.Clock,
			Started:        m.opts.Clock.Now(),
			Size:           length,
			sendFileNotify: m.opts.SendFileNotify,
		}
		if m.opts.DirectFileMode {
			inFile.PartialPath = partialPath
		}
		return inFile
	})
	if loaded {
		return 0, ErrFileExists
	}
	defer m.incomingFiles.Delete(inFileKey)
	m.deleter.Remove(filepath.Base(partialPath)) // avoid deleting the partial file while receiving

	// Create (if not already) the partial file with read-write permissions.
	f, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return 0, redactAndLogError("Create", err)
	}
	defer func() {
		f.Close() // best-effort to cleanup dangling file handles
		if err != nil {
			if avoidPartialRename {
				os.Remove(partialPath) // best-effort
				return
			}
			m.deleter.Insert(filepath.Base(partialPath)) // mark partial file for eventual deletion
		}
	}()
	inFile.W = f

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

	// Return early for avoidPartialRename since users of AvoidFinalRename
	// are depending on the exact naming of partial files.
	if avoidPartialRename {
		inFile.Mu.Lock()
		inFile.Done = true
		inFile.Mu.Unlock()
		m.totalReceived.Add(1)
		m.opts.SendFileNotify()
		return fileLength, nil
	}

	// File has been successfully received, rename the partial file
	// to the final destination filename. If a file of that name already exists,
	// then try multiple times with variations of the filename.
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
	}
	if maxRetries <= 0 {
		return 0, errors.New("too many retries trying to rename partial file")
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
