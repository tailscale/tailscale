// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tstime"
	"tailscale.com/version/distro"
)

type incomingFileKey struct {
	id   clientID
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

// PutFile stores a file into [manager.Dir] from a given client id.
// The baseName must be a base filename without any slashes.
// The length is the expected length of content to read from r,
// it may be negative to indicate that it is unknown.
// It returns the length of the entire file.
// If expectedHash is non-empty, it is the expected SHA-256 hash of the entire file
// content, and PutFile will verify that the hash matches after writing the file.
// If the hash does not match, PutFile will delete the partial file and return ErrConsentHashMismatch.
//
// If there is a failure reading from r, then the partial file is not deleted
// for some period of time. The [manager.PartialFiles] and [manager.HashPartialFile]
// methods may be used to list all partial files and to compute the hash for a
// specific partial file. This allows the client to determine whether to resume
// a partial file. While resuming, PutFile may be called again with a non-zero
// offset to specify where to resume receiving data at.
func (m *manager) PutFile(id clientID, baseName string, r io.Reader, offset, length int64, expectedHash string) (fileLength int64, err error) {
	switch {
	case m == nil || m.opts.fileOps == nil:
		return 0, ErrNoTaildrop
	case !envknob.CanTaildrop():
		return 0, ErrNoTaildrop
	case distro.Get() == distro.Unraid && !m.opts.DirectFileMode:
		return 0, ErrNotAccessible
	}

	if err := validateBaseName(baseName); err != nil {
		return 0, err
	}

	// and make sure we don't delete it while uploading:
	m.deleter.Remove(baseName)

	// Check whether there is an in-progress transfer for the file.
	inFileKey := incomingFileKey{id, baseName}
	inFile, loaded := m.incomingFiles.LoadOrInit(inFileKey, func() *incomingFile {
		inFile := &incomingFile{
			clock:          m.opts.Clock,
			started:        m.opts.Clock.Now(),
			size:           length,
			sendFileNotify: m.opts.SendFileNotify,
		}
		return inFile
	})

	if loaded {
		return 0, ErrFileExists
	}
	defer m.incomingFiles.Delete(inFileKey)

	// Create (if not already) the partial file with read-write permissions.
	partialName := baseName + id.partialSuffix()
	wc, partialPath, err := m.opts.fileOps.OpenWriter(partialName, offset, 0o666)
	if err != nil {
		return 0, m.redactAndLogError("Create", err)
	}
	defer func() {
		wc.Close()
		if err != nil {
			m.deleter.Insert(partialName) // mark partial file for eventual deletion
		}
	}()

	inFile.w = wc
	if m.opts.DirectFileMode {
		inFile.mu.Lock()
		inFile.partialPath = partialPath
		inFile.mu.Unlock()
	}

	// Record that we have started to receive at least one file.
	// This is used by the deleter upon a cold-start to scan the directory
	// for any files that need to be deleted.
	if st := m.opts.State; st != nil {
		if b, _ := st.ReadState(ipn.TaildropReceivedKey); len(b) == 0 {
			if werr := st.WriteState(ipn.TaildropReceivedKey, []byte{1}); werr != nil {
				m.opts.Logf("WriteState error: %v", werr) // non-fatal error
			}
		}
	}

	var h hash.Hash
	var dst io.Writer = wc
	if expectedHash != "" {
		h = sha256.New()
		if err := m.seedHashForPartialFile(partialName, offset, h); err != nil {
			return 0, err
		}
		dst = io.MultiWriter(wc, h)
	}

	// Copy the contents of the file to the writer.
	copyLength, err := io.Copy(dst, r)
	if err != nil {
		return offset + copyLength, m.redactAndLogError("Copy", err)
	}
	if length >= 0 && copyLength != length {
		return offset + copyLength, m.redactAndLogError("Copy", fmt.Errorf("copied %d bytes; expected %d", copyLength, length))
	}
	if err := wc.Close(); err != nil {
		return 0, m.redactAndLogError("Close", err)
	}

	if h != nil {
		if hex.EncodeToString(h.Sum(nil)) != expectedHash {
			if err := m.opts.fileOps.Remove(partialName); err != nil {
				m.opts.Logf("discarding mismatched file: %v", err)
			}
			return 0, ErrConsentHashMismatch
		}
	}
	fileLength = offset + copyLength

	finalPath, err := m.opts.fileOps.Rename(partialPath, baseName)
	if err != nil {
		return 0, m.redactAndLogError("Rename", err)
	}
	inFile.mu.Lock()
	inFile.done = true
	inFile.finalPath = finalPath
	inFile.mu.Unlock()

	m.totalReceived.Add(1)
	m.opts.SendFileNotify()
	return fileLength, nil
}

// seedHashForPartialFile Seeds the hash for a partial file up to the given offset into the provided hash writer.
// no-op for offset <= 0. Returns an error if the partial file cannot be opened or read.
func (m *manager) seedHashForPartialFile(partialName string, offset int64, h io.Writer) error {
	if offset <= 0 {
		return nil
	}

	rc, err := m.opts.fileOps.OpenReader(partialName)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(h, rc, offset)
	closeErr := rc.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (m *manager) redactAndLogError(stage string, err error) error {
	err = redactError(err)
	m.opts.Logf("put %s error: %v", stage, err)
	return err
}
