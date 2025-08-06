// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	switch {
	case m == nil || m.opts.Dir == "":
		return 0, ErrNoTaildrop
	case !envknob.CanTaildrop():
		return 0, ErrNoTaildrop
	case distro.Get() == distro.Unraid && !m.opts.DirectFileMode:
		return 0, ErrNotAccessible
	}

	//Compute dstPath & avoid mid‑upload deletion
	var dstPath string
	if m.opts.Mode == PutModeDirect {
		var err error
		dstPath, err = joinDir(m.opts.Dir, baseName)
		if err != nil {
			return 0, err
		}
	} else {
		// In SAF mode, we simply use the baseName as the destination "path"
		// (the actual directory is managed by SAF).
		dstPath = baseName
	}
	m.deleter.Remove(filepath.Base(dstPath)) // avoid deleting the partial file while receiving

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

	// Open writer & populate inFile paths
	wc, partialPath, err := m.openWriterAndPaths(id, m.opts.Mode, inFile, baseName, dstPath, offset)
	if err != nil {
		return 0, m.redactAndLogError("Create", err)
	}
	defer func() {
		wc.Close()
		if err != nil {
			m.deleter.Insert(filepath.Base(partialPath)) // mark partial file for eventual deletion
		}
	}()

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

	// Finalize rename
	switch m.opts.Mode {
	case PutModeDirect:
		var finalDst string
		finalDst, err = m.finalizeDirect(inFile, partialPath, dstPath, fileLength)
		if err != nil {
			return 0, m.redactAndLogError("Rename", err)
		}
		inFile.finalPath = finalDst

	case PutModeAndroidSAF:
		if err = m.finalizeSAF(partialPath, baseName); err != nil {
			return 0, m.redactAndLogError("Rename", err)
		}
	}

	m.totalReceived.Add(1)
	m.opts.SendFileNotify()
	return fileLength, nil
}

// openWriterAndPaths opens the correct writer, seeks/truncates if needed,
// and sets inFile.partialPath & inFile.finalPath for later cleanup/rename.
// The caller is responsible for closing the file on completion.
func (m *manager) openWriterAndPaths(
	id clientID,
	mode PutMode,
	inFile *incomingFile,
	baseName string,
	dstPath string,
	offset int64,
) (wc io.WriteCloser, partialPath string, err error) {
	switch mode {

	case PutModeDirect:
		partialPath = dstPath + id.partialSuffix()
		f, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o666)
		if err != nil {
			return nil, "", m.redactAndLogError("Create", err)
		}
		if offset != 0 {
			curr, err := f.Seek(0, io.SeekEnd)
			if err != nil {
				f.Close()
				return nil, "", m.redactAndLogError("Seek", err)
			}
			if offset < 0 || offset > curr {
				f.Close()
				return nil, "", m.redactAndLogError("Seek", fmt.Errorf("offset %d out of range", offset))
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				return nil, "", m.redactAndLogError("Seek", err)
			}
			if err := f.Truncate(offset); err != nil {
				f.Close()
				return nil, "", m.redactAndLogError("Truncate", err)
			}
		}
		inFile.w = f
		wc = f
		inFile.partialPath = partialPath
		inFile.finalPath = dstPath
		return wc, partialPath, nil

	case PutModeAndroidSAF:
		if m.opts.FileOps == nil {
			return nil, "", m.redactAndLogError("Create (SAF)", fmt.Errorf("missing FileOps"))
		}
		writer, uri, err := m.opts.FileOps.OpenFileWriter(baseName)
		if err != nil {
			return nil, "", m.redactAndLogError("Create (SAF)", fmt.Errorf("failed to open file for writing via SAF"))
		}
		if writer == nil || uri == "" {
			return nil, "", fmt.Errorf("invalid SAF writer or URI")
		}
		// SAF mode does not support resuming, so enforce offset == 0.
		if offset != 0 {
			writer.Close()
			return nil, "", m.redactAndLogError("Seek", fmt.Errorf("resuming is not supported in SAF mode"))
		}
		inFile.w = writer
		wc = writer
		partialPath = uri
		inFile.partialPath = uri
		inFile.finalPath = baseName
		return wc, partialPath, nil

	default:
		return nil, "", fmt.Errorf("unsupported PutMode: %v", mode)
	}
}

// finalizeDirect atomically renames or dedups the partial file, retrying
// under new names up to 10 times. It returns the final path that succeeded.
func (m *manager) finalizeDirect(
	inFile *incomingFile,
	partialPath string,
	initialDst string,
	fileLength int64,
) (string, error) {
	var (
		once       sync.Once
		cachedSum  [sha256.Size]byte
		cacheErr   error
		computeSum = func() ([sha256.Size]byte, error) {
			once.Do(func() { cachedSum, cacheErr = sha256File(partialPath) })
			return cachedSum, cacheErr
		}
	)

	dstPath := initialDst
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		// Atomically rename the partial file as the destination file if it doesn't exist.
		// Otherwise, it returns the length of the current destination file.
		// The operation is atomic.
		lengthOnDisk, err := func() (int64, error) {
			m.renameMu.Lock()
			defer m.renameMu.Unlock()
			fi, statErr := os.Stat(dstPath)
			if os.IsNotExist(statErr) {
				// dst missing → rename partial into place
				return -1, os.Rename(partialPath, dstPath)
			}
			if statErr != nil {
				return -1, statErr
			}
			return fi.Size(), nil
		}()
		if err != nil {
			return "", err
		}
		if lengthOnDisk < 0 {
			// successfully moved
			inFile.finalPath = dstPath
			return dstPath, nil
		}

		// Avoid the final rename if a destination file has the same contents.
		//
		// Note: this is best effort and copying files from iOS from the Media Library
		// results in processing on the iOS side which means the size and shas of the
		// same file can be different.
		if lengthOnDisk == fileLength {
			partSum, err := computeSum()
			if err != nil {
				return "", err
			}
			dstSum, err := sha256File(dstPath)
			if err != nil {
				return "", err
			}
			if partSum == dstSum {
				// same content → drop the partial
				if err := os.Remove(partialPath); err != nil {
					return "", err
				}
				inFile.finalPath = dstPath
				return dstPath, nil
			}
		}

		// Choose a new destination filename and try again.
		dstPath = nextFilename(dstPath)
	}

	return "", fmt.Errorf("too many retries trying to rename a partial file %q", initialDst)
}

// finalizeSAF retries RenamePartialFile up to 10 times, generating a new
// name on each failure until the SAF URI changes.
func (m *manager) finalizeSAF(
	partialPath, finalName string,
) error {
	if m.opts.FileOps == nil {
		return fmt.Errorf("missing FileOps for SAF finalize")
	}
	const maxTries = 10
	name := finalName
	for i := 0; i < maxTries; i++ {
		newURI, err := m.opts.FileOps.RenamePartialFile(partialPath, m.opts.Dir, name)
		if err != nil {
			return err
		}
		if newURI != "" && newURI != name {
			return nil
		}
		name = nextFilename(name)
	}
	return fmt.Errorf("failed to finalize SAF file after %d retries", maxTries)
}

func (m *manager) redactAndLogError(stage string, err error) error {
	err = redactError(err)
	m.opts.Logf("put %s error: %v", stage, err)
	return err
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
