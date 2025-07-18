// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"fmt"
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
//
// If there is a failure reading from r, then the partial file is not deleted
// for some period of time. The [manager.PartialFiles] and [manager.HashPartialFile]
// methods may be used to list all partial files and to compute the hash for a
// specific partial file. This allows the client to determine whether to resume
// a partial file. While resuming, PutFile may be called again with a non-zero
// offset to specify where to resume receiving data at.
func (m *manager) PutFile(id clientID, baseName string, r io.Reader, offset, length int64) (int64, error) {
	fo := m.opts.FileOps
	switch {
	case m == nil || m.opts.Dir == "" || fo == nil:
		return 0, ErrNoTaildrop
	case !envknob.CanTaildrop():
		return 0, ErrNoTaildrop
	case distro.Get() == distro.Unraid && !m.opts.DirectFileMode:
		return 0, ErrNotAccessible
	}

	dstID, err := joinDir(m.opts.Dir, baseName)
	if err != nil {
		return 0, err
	}
	// and make sure we don't delete it while uploading:
	m.deleter.Remove(fo.Base(dstID))

	// Check whether there is an in-progress transfer for the file.
	partialFileKey := incomingFileKey{id, baseName}
	inFile, loaded := m.incomingFiles.LoadOrInit(partialFileKey, func() *incomingFile {
		return &incomingFile{
			clock:          m.opts.Clock,
			started:        m.opts.Clock.Now(),
			size:           length,
			sendFileNotify: m.opts.SendFileNotify,
		}
	})
	if loaded {
		return 0, ErrFileExists
	}
	defer m.incomingFiles.Delete(partialFileKey)

	// Open writer & populate inFile paths (might be a .part file or SAF URI)
	wc, partialPath, err := fo.OpenWriter(baseName+id.partialSuffix(), offset, 0o666)
	if err != nil {
		return 0, m.redactAndLogError("Create", err)
	}
	defer func() {
		wc.Close()
		if err != nil {
			m.deleter.Insert(fo.Base(partialPath)) // mark partial file for eventual deletion
		}
	}()

	inFile.w = wc
	inFile.partialPath = partialPath
	inFile.finalPath = dstID

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

	// Copy the contents of the file to the writer.
	copyLength, err := io.Copy(wc, r)
	if err != nil {
		return 0, m.redactAndLogError("Copy", err)
	}
	if length >= 0 && copyLength != length {
		return 0, m.redactAndLogError("Copy", fmt.Errorf("copied %d bytes; expected %d", copyLength, length))
	}
	if err := wc.Close(); err != nil {
		return 0, m.redactAndLogError("Close", err)
	}

	fileLength := offset + copyLength

	inFile.mu.Lock()
	inFile.done = true
	inFile.mu.Unlock()

	// 6) Finalize (rename/move) the partial into place via FileOps.Rename
	newID, err := fo.Rename(partialPath, baseName)
	if err != nil {
		return 0, m.redactAndLogError("Rename", err)
	}
	inFile.finalPath = newID

	m.totalReceived.Add(1)
	m.opts.SendFileNotify()
	return fileLength, nil
}

func (m *manager) redactAndLogError(stage string, err error) error {
	err = redactError(err)
	m.opts.Logf("put %s error: %v", stage, err)
	return err
}
