// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/logtail/backoff"
)

// HasFilesWaiting reports whether any files are buffered in [Handler.Dir].
// This always returns false when [Handler.DirectFileMode] is false.
func (m *Manager) HasFilesWaiting() bool {
	if m == nil || m.Dir == "" || m.DirectFileMode {
		return false
	}
	if m.knownEmpty.Load() {
		// Optimization: this is usually empty, so avoid opening
		// the directory and checking. We can't cache the actual
		// has-files-or-not values as the macOS/iOS client might
		// in the future use+delete the files directly. So only
		// keep this negative cache.
		return false
	}
	f, err := os.Open(m.Dir)
	if err != nil {
		return false
	}
	defer f.Close()
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			name := de.Name()
			if strings.HasSuffix(name, partialSuffix) {
				continue
			}
			if name, ok := strings.CutSuffix(name, deletedSuffix); ok { // for Windows + tests
				// After we're done looping over files, then try
				// to delete this file. Don't do it proactively,
				// as the OS may return "foo.jpg.deleted" before "foo.jpg"
				// and we don't want to delete the ".deleted" file before
				// enumerating to the "foo.jpg" file.
				defer tryDeleteAgain(filepath.Join(m.Dir, name))
				continue
			}
			if de.Type().IsRegular() {
				_, err := os.Stat(filepath.Join(m.Dir, name+deletedSuffix))
				if os.IsNotExist(err) {
					return true
				}
				if err == nil {
					tryDeleteAgain(filepath.Join(m.Dir, name))
					continue
				}
			}
		}
		if err == io.EOF {
			m.knownEmpty.Store(true)
		}
		if err != nil {
			break
		}
	}
	return false
}

// WaitingFiles returns the list of files that have been sent by a
// peer that are waiting in [Handler.Dir].
// This always returns nil when [Handler.DirectFileMode] is false.
func (m *Manager) WaitingFiles() (ret []apitype.WaitingFile, err error) {
	if m == nil || m.Dir == "" {
		return nil, ErrNoTaildrop
	}
	if m.DirectFileMode {
		return nil, nil
	}
	f, err := os.Open(m.Dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var deleted map[string]bool // "foo.jpg" => true (if "foo.jpg.deleted" exists)
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			name := de.Name()
			if strings.HasSuffix(name, partialSuffix) {
				continue
			}
			if name, ok := strings.CutSuffix(name, deletedSuffix); ok { // for Windows + tests
				if deleted == nil {
					deleted = map[string]bool{}
				}
				deleted[name] = true
				continue
			}
			if de.Type().IsRegular() {
				fi, err := de.Info()
				if err != nil {
					continue
				}
				ret = append(ret, apitype.WaitingFile{
					Name: filepath.Base(name),
					Size: fi.Size(),
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(deleted) > 0 {
		// Filter out any return values "foo.jpg" where a
		// "foo.jpg.deleted" marker file exists on disk.
		all := ret
		ret = ret[:0]
		for _, wf := range all {
			if !deleted[wf.Name] {
				ret = append(ret, wf)
			}
		}
		// And do some opportunistic deleting while we're here.
		// Maybe Windows is done virus scanning the file we tried
		// to delete a long time ago and will let us delete it now.
		for name := range deleted {
			tryDeleteAgain(filepath.Join(m.Dir, name))
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Name < ret[j].Name })
	return ret, nil
}

// tryDeleteAgain tries to delete path (and path+deletedSuffix) after
// it failed earlier.  This happens on Windows when various anti-virus
// tools hook into filesystem operations and have the file open still
// while we're trying to delete it. In that case we instead mark it as
// deleted (writing a "foo.jpg.deleted" marker file), but then we
// later try to clean them up.
//
// fullPath is the full path to the file without the deleted suffix.
func tryDeleteAgain(fullPath string) {
	if err := os.Remove(fullPath); err == nil || os.IsNotExist(err) {
		os.Remove(fullPath + deletedSuffix)
	}
}

// DeleteFile deletes a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *Manager) DeleteFile(baseName string) error {
	if m == nil || m.Dir == "" {
		return ErrNoTaildrop
	}
	if m.DirectFileMode {
		return errors.New("deletes not allowed in direct mode")
	}
	path, err := m.joinDir(baseName)
	if err != nil {
		return err
	}
	var bo *backoff.Backoff
	logf := m.Logf
	t0 := m.Clock.Now()
	for {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			err = redactErr(err)
			// Put a retry loop around deletes on Windows. Windows
			// file descriptor closes are effectively asynchronous,
			// as a bunch of hooks run on/after close, and we can't
			// necessarily delete the file for a while after close,
			// as we need to wait for everybody to be done with
			// it. (on Windows, unlike Unix, a file can't be deleted
			// if it's open anywhere)
			// So try a few times but ultimately just leave a
			// "foo.jpg.deleted" marker file to note that it's
			// deleted and we clean it up later.
			if runtime.GOOS == "windows" {
				if bo == nil {
					bo = backoff.NewBackoff("delete-retry", logf, 1*time.Second)
				}
				if m.Clock.Since(t0) < 5*time.Second {
					bo.BackOff(context.Background(), err)
					continue
				}
				if err := touchFile(path + deletedSuffix); err != nil {
					logf("peerapi: failed to leave deleted marker: %v", err)
				}
			}
			logf("peerapi: failed to DeleteFile: %v", err)
			return err
		}
		return nil
	}
}

func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return redactErr(err)
	}
	return f.Close()
}

// OpenFile opens a file of the given baseName from [Handler.Dir].
// This method is only allowed when [Handler.DirectFileMode] is false.
func (m *Manager) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if m == nil || m.Dir == "" {
		return nil, 0, ErrNoTaildrop
	}
	if m.DirectFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	path, err := m.joinDir(baseName)
	if err != nil {
		return nil, 0, err
	}
	if fi, err := os.Stat(path + deletedSuffix); err == nil && fi.Mode().IsRegular() {
		tryDeleteAgain(path)
		return nil, 0, &fs.PathError{Op: "open", Path: redacted, Err: fs.ErrNotExist}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, redactErr(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, redactErr(err)
	}
	return f, fi.Size(), nil
}
