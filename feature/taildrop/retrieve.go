// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/backoff"
	"tailscale.com/util/set"
)

// HasFilesWaiting reports whether any files are buffered in [Handler.Dir].
// This always returns false when [Handler.DirectFileMode] is false.
func (m *manager) HasFilesWaiting() bool {
	if m == nil || m.opts.fileOps == nil || m.opts.DirectFileMode {
		return false
	}

	// Optimization: this is usually empty, so avoid opening
	// the directory and checking. We can't cache the actual
	// has-files-or-not values as the macOS/iOS client might
	// in the future use+delete the files directly. So only
	// keep this negative cache.
	total := m.totalReceived.Load()
	if total == m.emptySince.Load() {
		return false
	}

	files, err := m.opts.fileOps.ListFiles()
	if err != nil {
		return false
	}

	// Build a set of filenames present in Dir
	fileSet := set.Of(files...)

	for _, filename := range files {
		if isPartialOrDeleted(filename) {
			continue
		}
		if fileSet.Contains(filename + deletedSuffix) {
			continue // already handled
		}
		// Found at least one downloadable file
		return true
	}

	// No waiting files → update negative‑result cache
	m.emptySince.Store(total)
	return false
}

// WaitingFiles returns the list of files that have been sent by a
// peer that are waiting in [Handler.Dir].
// This always returns nil when [Handler.DirectFileMode] is false.
func (m *manager) WaitingFiles() ([]apitype.WaitingFile, error) {
	if m == nil || m.opts.fileOps == nil {
		return nil, ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return nil, nil
	}
	names, err := m.opts.fileOps.ListFiles()
	if err != nil {
		return nil, redactError(err)
	}
	var ret []apitype.WaitingFile
	for _, name := range names {
		if isPartialOrDeleted(name) {
			continue
		}
		// A corresponding .deleted marker means the file was already handled.
		if _, err := m.opts.fileOps.Stat(name + deletedSuffix); err == nil {
			continue
		}
		fi, err := m.opts.fileOps.Stat(name)
		if err != nil {
			continue
		}
		ret = append(ret, apitype.WaitingFile{
			Name: name,
			Size: fi.Size(),
		})
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Name < ret[j].Name })
	return ret, nil
}

// DeleteFile deletes a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *manager) DeleteFile(baseName string) error {
	if m == nil || m.opts.fileOps == nil {
		return ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return errors.New("deletes not allowed in direct mode")
	}

	var bo *backoff.Backoff
	logf := m.opts.Logf
	t0 := m.opts.Clock.Now()
	for {
		err := m.opts.fileOps.Remove(baseName)
		if err != nil && !os.IsNotExist(err) {
			err = redactError(err)
			// Put a retry loop around deletes on Windows.
			//
			// Windows file descriptor closes are effectively asynchronous,
			// as a bunch of hooks run on/after close,
			// and we can't necessarily delete the file for a while after close,
			// as we need to wait for everybody to be done with it.
			// On Windows, unlike Unix, a file can't be deleted if it's open anywhere.
			// So try a few times but ultimately just leave a "foo.jpg.deleted"
			// marker file to note that it's deleted and we clean it up later.
			if runtime.GOOS == "windows" {
				if bo == nil {
					bo = backoff.NewBackoff("delete-retry", logf, 1*time.Second)
				}
				if m.opts.Clock.Since(t0) < 5*time.Second {
					bo.BackOff(context.Background(), err)
					continue
				}
				if err := m.touchFile(baseName + deletedSuffix); err != nil {
					logf("peerapi: failed to leave deleted marker: %v", err)
				}
				m.deleter.Insert(baseName + deletedSuffix)
			}
			logf("peerapi: failed to DeleteFile: %v", err)
			return err
		}
		return nil
	}
}

func (m *manager) touchFile(name string) error {
	wc, _, err := m.opts.fileOps.OpenWriter(name /* offset= */, 0, 0666)
	if err != nil {
		return redactError(err)
	}
	return wc.Close()
}

// OpenFile opens a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *manager) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if m == nil || m.opts.fileOps == nil {
		return nil, 0, ErrNoTaildrop
	}
	if m.opts.DirectFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	if _, err := m.opts.fileOps.Stat(baseName + deletedSuffix); err == nil {
		return nil, 0, redactError(&fs.PathError{Op: "open", Path: baseName, Err: fs.ErrNotExist})
	}
	f, err := m.opts.fileOps.OpenReader(baseName)
	if err != nil {
		return nil, 0, redactError(err)
	}
	fi, err := m.opts.fileOps.Stat(baseName)
	if err != nil {
		f.Close()
		return nil, 0, redactError(err)
	}
	return f, fi.Size(), nil
}
