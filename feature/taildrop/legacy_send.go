// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

// These entrypoints preserve production behavior until the full taildrop consent flow
// is complete and available for all clients.

import (
	"fmt"
	"io"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/version/distro"
)

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
func (m *manager) legacyPutFile(id clientID, baseName string, r io.Reader, offset, length int64) (fileLength int64, err error) {

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

	m.deleter.Remove(baseName)

	partialName := baseName + id.partialSuffix()
	wc, partialPath, err := m.opts.fileOps.OpenWriter(partialName, offset, 0o666)
	if err != nil {
		return 0, m.redactAndLogError("Create", err)
	}
	defer func() {
		wc.Close()
		if err != nil {
			m.deleter.Insert(partialName)
		}
	}()

	inFileKey := incomingFileKey{id, baseName}
	inFile, loaded := m.incomingFiles.LoadOrInit(inFileKey, func() *incomingFile {
		inFile := &incomingFile{
			clock:          m.opts.Clock,
			started:        m.opts.Clock.Now(),
			size:           length,
			sendFileNotify: m.opts.SendFileNotify,
		}
		if m.opts.DirectFileMode {
			inFile.partialPath = partialPath
		}
		return inFile
	})

	inFile.w = wc

	if loaded {
		return 0, ErrFileExists
	}
	defer m.incomingFiles.Delete(inFileKey)

	if st := m.opts.State; st != nil {
		if b, _ := st.ReadState(ipn.TaildropReceivedKey); len(b) == 0 {
			if werr := st.WriteState(ipn.TaildropReceivedKey, []byte{1}); werr != nil {
				m.opts.Logf("WriteState error: %v", werr)
			}
		}
	}

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

	fileLength = offset + copyLength

	inFile.mu.Lock()
	inFile.done = true
	inFile.mu.Unlock()

	finalPath, err := m.opts.fileOps.Rename(partialPath, baseName)
	if err != nil {
		return 0, m.redactAndLogError("Rename", err)
	}
	inFile.finalPath = finalPath

	m.totalReceived.Add(1)
	m.opts.SendFileNotify()
	return fileLength, nil
}
