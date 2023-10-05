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

// HasFilesWaiting reports whether any files are buffered in the
// tailscaled daemon storage.
func (s *Handler) HasFilesWaiting() bool {
	if s == nil || s.RootDir == "" || s.DirectFileMode {
		return false
	}
	if s.KnownEmpty.Load() {
		// Optimization: this is usually empty, so avoid opening
		// the directory and checking. We can't cache the actual
		// has-files-or-not values as the macOS/iOS client might
		// in the future use+delete the files directly. So only
		// keep this negative cache.
		return false
	}
	f, err := os.Open(s.RootDir)
	if err != nil {
		return false
	}
	defer f.Close()
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			name := de.Name()
			if strings.HasSuffix(name, PartialSuffix) {
				continue
			}
			if name, ok := strings.CutSuffix(name, deletedSuffix); ok { // for Windows + tests
				// After we're done looping over files, then try
				// to delete this file. Don't do it proactively,
				// as the OS may return "foo.jpg.deleted" before "foo.jpg"
				// and we don't want to delete the ".deleted" file before
				// enumerating to the "foo.jpg" file.
				defer tryDeleteAgain(filepath.Join(s.RootDir, name))
				continue
			}
			if de.Type().IsRegular() {
				_, err := os.Stat(filepath.Join(s.RootDir, name+deletedSuffix))
				if os.IsNotExist(err) {
					return true
				}
				if err == nil {
					tryDeleteAgain(filepath.Join(s.RootDir, name))
					continue
				}
			}
		}
		if err == io.EOF {
			s.KnownEmpty.Store(true)
		}
		if err != nil {
			break
		}
	}
	return false
}

// WaitingFiles returns the list of files that have been sent by a
// peer that are waiting in the buffered "pick up" directory owned by
// the Tailscale daemon.
//
// As a side effect, it also does any lazy deletion of files as
// required by Windows.
func (s *Handler) WaitingFiles() (ret []apitype.WaitingFile, err error) {
	if s == nil {
		return nil, errNilHandler
	}
	if s.RootDir == "" {
		return nil, ErrNoTaildrop
	}
	if s.DirectFileMode {
		return nil, nil
	}
	f, err := os.Open(s.RootDir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var deleted map[string]bool // "foo.jpg" => true (if "foo.jpg.deleted" exists)
	for {
		des, err := f.ReadDir(10)
		for _, de := range des {
			name := de.Name()
			if strings.HasSuffix(name, PartialSuffix) {
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
			tryDeleteAgain(filepath.Join(s.RootDir, name))
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

func (s *Handler) DeleteFile(baseName string) error {
	if s == nil {
		return errNilHandler
	}
	if s.RootDir == "" {
		return ErrNoTaildrop
	}
	if s.DirectFileMode {
		return errors.New("deletes not allowed in direct mode")
	}
	path, ok := s.DiskPath(baseName)
	if !ok {
		return errors.New("bad filename")
	}
	var bo *backoff.Backoff
	logf := s.Logf
	t0 := s.Clock.Now()
	for {
		err := os.Remove(path)
		if err != nil && !os.IsNotExist(err) {
			err = RedactErr(err)
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
				if s.Clock.Since(t0) < 5*time.Second {
					bo.BackOff(context.Background(), err)
					continue
				}
				if err := TouchFile(path + deletedSuffix); err != nil {
					logf("peerapi: failed to leave deleted marker: %v", err)
				}
			}
			logf("peerapi: failed to DeleteFile: %v", err)
			return err
		}
		return nil
	}
}

func TouchFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return RedactErr(err)
	}
	return f.Close()
}

func (s *Handler) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if s == nil {
		return nil, 0, errNilHandler
	}
	if s.RootDir == "" {
		return nil, 0, ErrNoTaildrop
	}
	if s.DirectFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	path, ok := s.DiskPath(baseName)
	if !ok {
		return nil, 0, errors.New("bad filename")
	}
	if fi, err := os.Stat(path + deletedSuffix); err == nil && fi.Mode().IsRegular() {
		tryDeleteAgain(path)
		return nil, 0, &fs.PathError{Op: "open", Path: redacted, Err: fs.ErrNotExist}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, RedactErr(err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, RedactErr(err)
	}
	return f, fi.Size(), nil
}
