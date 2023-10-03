// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"context"
	"errors"
	"hash/adler32"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/logtail/backoff"
	"tailscale.com/tailcfg"
	"tailscale.com/util/multierr"
	"tailscale.com/version/distro"
)

const (
	// partialSuffix is the suffix appended to files while they're
	// still in the process of being transferred.
	partialSuffix = ".partial"

	// deletedSuffix is the suffix for a deleted marker file
	// that's placed next to a file (without the suffix) that we
	// tried to delete, but Windows wouldn't let us. These are
	// only written on Windows (and in tests), but they're not
	// permitted to be uploaded directly on any platform, like
	// partial files.
	deletedSuffix = ".deleted"
)

func validFilenameRune(r rune) bool {
	switch r {
	case '/':
		return false
	case '\\', ':', '*', '"', '<', '>', '|':
		// Invalid stuff on Windows, but we reject them everywhere
		// for now.
		// TODO(bradfitz): figure out a better plan. We initially just
		// wrote things to disk URL path-escaped, but that's gross
		// when debugging, and just moves the problem to callers.
		// So now we put the UTF-8 filenames on disk directly as
		// sent.
		return false
	}
	return unicode.IsPrint(r)
}

func approxSize(n int64) string {
	if n <= 1<<10 {
		return "<=1KB"
	}
	if n <= 1<<20 {
		return "<=1MB"
	}
	return fmt.Sprintf("~%dMB", n>>20)
}

type peerAPIServer struct {
	*ipnlocal.PeerAPIServer
}

func (s *peerAPIServer) diskPath(baseName string) (fullPath string, ok bool) {
	if !utf8.ValidString(baseName) {
		return "", false
	}
	if strings.TrimSpace(baseName) != baseName {
		return "", false
	}
	if len(baseName) > 255 {
		return "", false
	}
	// TODO: validate unicode normalization form too? Varies by platform.
	clean := path.Clean(baseName)
	if clean != baseName ||
		clean == "." || clean == ".." ||
		strings.HasSuffix(clean, deletedSuffix) ||
		strings.HasSuffix(clean, partialSuffix) {
		return "", false
	}
	for _, r := range baseName {
		if !validFilenameRune(r) {
			return "", false
		}
	}
	if !filepath.IsLocal(baseName) {
		return "", false
	}
	return filepath.Join(s.rootDir, baseName), true
}

// redacted is a fake path name we use in errors, to avoid
// accidentally logging actual filenames anywhere.
const redacted = "redacted"

type redactedErr struct {
	msg   string
	inner error
}

func (re *redactedErr) Error() string {
	return re.msg
}

func (re *redactedErr) Unwrap() error {
	return re.inner
}

func redactString(s string) string {
	hash := adler32.Checksum([]byte(s))

	var buf [len(redacted) + len(".12345678")]byte
	b := append(buf[:0], []byte(redacted)...)
	b = append(b, '.')
	b = strconv.AppendUint(b, uint64(hash), 16)
	return string(b)
}

func redactErr(root error) error {
	// redactStrings is a list of sensitive strings that were redacted.
	// It is not sufficient to just snub out sensitive fields in Go errors
	// since some wrapper errors like fmt.Errorf pre-cache the error string,
	// which would unfortunately remain unaffected.
	var redactStrings []string

	// Redact sensitive fields in known Go error types.
	var unknownErrors int
	multierr.Range(root, func(err error) bool {
		switch err := err.(type) {
		case *os.PathError:
			redactStrings = append(redactStrings, err.Path)
			err.Path = redactString(err.Path)
		case *os.LinkError:
			redactStrings = append(redactStrings, err.New, err.Old)
			err.New = redactString(err.New)
			err.Old = redactString(err.Old)
		default:
			unknownErrors++
		}
		return true
	})

	// If there are no redacted strings or no unknown error types,
	// then we can return the possibly modified root error verbatim.
	// Otherwise, we must replace redacted strings from any wrappers.
	if len(redactStrings) == 0 || unknownErrors == 0 {
		return root
	}

	// Stringify and replace any paths that we found above, then return
	// the error wrapped in a type that uses the newly-redacted string
	// while also allowing Unwrap()-ing to the inner error type(s).
	s := root.Error()
	for _, toRedact := range redactStrings {
		s = strings.ReplaceAll(s, toRedact, redactString(toRedact))
	}
	return &redactedErr{msg: s, inner: root}
}

type peerAPIHandler struct {
	*ipnlocal.PeerAPIHandler
}

// WaitingFiles returns the list of files that have been sent by a
// peer that are waiting in the buffered "pick up" directory owned by
// the Tailscale daemon.
//
// As a side effect, it also does any lazy deletion of files as
// required by Windows.
func (s *peerAPIServer) WaitingFiles() (ret []apitype.WaitingFile, err error) {
	if s == nil {
		return nil, errNilPeerAPIServer
	}
	if s.rootDir == "" {
		return nil, errNoTaildrop
	}
	if s.directFileMode {
		return nil, nil
	}
	f, err := os.Open(s.rootDir)
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
			tryDeleteAgain(filepath.Join(s.rootDir, name))
		}
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].Name < ret[j].Name })
	return ret, nil
}

var (
	errNilPeerAPIServer = errors.New("peerapi unavailable; not listening")
	errNoTaildrop       = errors.New("Taildrop disabled; no storage directory")
)

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

func (s *peerAPIServer) DeleteFile(baseName string) error {
	if s == nil {
		return errNilPeerAPIServer
	}
	if s.rootDir == "" {
		return errNoTaildrop
	}
	if s.directFileMode {
		return errors.New("deletes not allowed in direct mode")
	}
	path, ok := s.diskPath(baseName)
	if !ok {
		return errors.New("bad filename")
	}
	var bo *backoff.Backoff
	logf := s.b.logf
	t0 := s.b.clock.Now()
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
				if s.b.clock.Since(t0) < 5*time.Second {
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

// hasFilesWaiting reports whether any files are buffered in the
// tailscaled daemon storage.
func (s *peerAPIServer) hasFilesWaiting() bool {
	if s == nil || s.rootDir == "" || s.directFileMode {
		return false
	}
	if s.knownEmpty.Load() {
		// Optimization: this is usually empty, so avoid opening
		// the directory and checking. We can't cache the actual
		// has-files-or-not values as the macOS/iOS client might
		// in the future use+delete the files directly. So only
		// keep this negative cache.
		return false
	}
	f, err := os.Open(s.rootDir)
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
				defer tryDeleteAgain(filepath.Join(s.rootDir, name))
				continue
			}
			if de.Type().IsRegular() {
				_, err := os.Stat(filepath.Join(s.rootDir, name+deletedSuffix))
				if os.IsNotExist(err) {
					return true
				}
				if err == nil {
					tryDeleteAgain(filepath.Join(s.rootDir, name))
					continue
				}
			}
		}
		if err == io.EOF {
			s.knownEmpty.Store(true)
		}
		if err != nil {
			break
		}
	}
	return false
}

func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return redactErr(err)
	}
	return f.Close()
}

func (s *peerAPIServer) OpenFile(baseName string) (rc io.ReadCloser, size int64, err error) {
	if s == nil {
		return nil, 0, errNilPeerAPIServer
	}
	if s.rootDir == "" {
		return nil, 0, errNoTaildrop
	}
	if s.directFileMode {
		return nil, 0, errors.New("opens not allowed in direct mode")
	}
	path, ok := s.diskPath(baseName)
	if !ok {
		return nil, 0, errors.New("bad filename")
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

type incomingFile struct {
	name        string // "foo.jpg"
	started     time.Time
	size        int64     // or -1 if unknown; never 0
	w           io.Writer // underlying writer
	ph          ipnlocal.PeerAPIHandler
	partialPath string // non-empty in direct mode

	mu         sync.Mutex
	copied     int64
	done       bool
	lastNotify time.Time
}

func (f *incomingFile) markAndNotifyDone() {
	f.mu.Lock()
	f.done = true
	f.mu.Unlock()
	b := f.ph.ps.b
	b.sendFileNotify()
}

func (f *incomingFile) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)

	b := f.ph.ps.b
	var needNotify bool
	defer func() {
		if needNotify {
			b.sendFileNotify()
		}
	}()
	if n > 0 {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.copied += int64(n)
		now := b.clock.Now()
		if f.lastNotify.IsZero() || now.Sub(f.lastNotify) > time.Second {
			f.lastNotify = now
			needNotify = true
		}
	}
	return n, err
}

func (f *incomingFile) PartialFile() ipn.PartialFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ipn.PartialFile{
		Name:         f.name,
		Started:      f.started,
		DeclaredSize: f.size,
		Received:     f.copied,
		PartialPath:  f.partialPath,
		Done:         f.done,
	}
}

// canPutFile reports whether h can put a file ("Taildrop") to this node.
func (h *peerAPIHandler) canPutFile() bool {
	if h.peerNode.UnsignedPeerAPIOnly() {
		// Unsigned peers can't send files.
		return false
	}
	return h.isSelf || h.peerHasCap(tailcfg.PeerCapabilityFileSharingSend)
}

func (h *peerAPIHandler) handlePeerPut(w http.ResponseWriter, r *http.Request) {
	if !envknob.CanTaildrop() {
		http.Error(w, "Taildrop disabled on device", http.StatusForbidden)
		return
	}
	if !h.canPutFile() {
		http.Error(w, "Taildrop access denied", http.StatusForbidden)
		return
	}
	if !h.ps.b.hasCapFileSharing() {
		http.Error(w, "file sharing not enabled by Tailscale admin", http.StatusForbidden)
		return
	}
	if r.Method != "PUT" {
		http.Error(w, "expected method PUT", http.StatusMethodNotAllowed)
		return
	}
	if h.ps.rootDir == "" {
		http.Error(w, errNoTaildrop.Error(), http.StatusInternalServerError)
		return
	}
	if distro.Get() == distro.Unraid && !h.ps.directFileMode {
		http.Error(w, "Taildrop folder not configured or accessible", http.StatusInternalServerError)
		return
	}
	rawPath := r.URL.EscapedPath()
	suffix, ok := strings.CutPrefix(rawPath, "/v0/put/")
	if !ok {
		http.Error(w, "misconfigured internals", 500)
		return
	}
	if suffix == "" {
		http.Error(w, "empty filename", 400)
		return
	}
	if strings.Contains(suffix, "/") {
		http.Error(w, "directories not supported", 400)
		return
	}
	baseName, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad path encoding", 400)
		return
	}
	dstFile, ok := h.ps.diskPath(baseName)
	if !ok {
		http.Error(w, "bad filename", 400)
		return
	}
	t0 := h.ps.b.clock.Now()
	// TODO(bradfitz): prevent same filename being sent by two peers at once

	// prevent same filename being sent twice
	if _, err := os.Stat(dstFile); err == nil {
		http.Error(w, "file exists", http.StatusConflict)
		return
	}

	partialFile := dstFile + partialSuffix
	f, err := os.Create(partialFile)
	if err != nil {
		h.logf("put Create error: %v", redactErr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var success bool
	defer func() {
		if !success {
			os.Remove(partialFile)
		}
	}()
	var finalSize int64
	var inFile *incomingFile
	if r.ContentLength != 0 {
		inFile = &incomingFile{
			name:    baseName,
			started: h.ps.b.clock.Now(),
			size:    r.ContentLength,
			w:       f,
			ph:      h,
		}
		if h.ps.directFileMode {
			inFile.partialPath = partialFile
		}
		h.ps.b.registerIncomingFile(inFile, true)
		defer h.ps.b.registerIncomingFile(inFile, false)
		n, err := io.Copy(inFile, r.Body)
		if err != nil {
			err = redactErr(err)
			f.Close()
			h.logf("put Copy error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		finalSize = n
	}
	if err := redactErr(f.Close()); err != nil {
		h.logf("put Close error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if h.ps.directFileMode && !h.ps.directFileDoFinalRename {
		if inFile != nil { // non-zero length; TODO: notify even for zero length
			inFile.markAndNotifyDone()
		}
	} else {
		if err := os.Rename(partialFile, dstFile); err != nil {
			err = redactErr(err)
			h.logf("put final rename: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	d := h.ps.b.clock.Since(t0).Round(time.Second / 10)
	h.logf("got put of %s in %v from %v/%v", approxSize(finalSize), d, h.remoteAddr.Addr(), h.peerNode.ComputedName)

	// TODO: set modtime
	// TODO: some real response
	success = true
	io.WriteString(w, "{}\n")
	h.ps.knownEmpty.Store(false)
	h.ps.b.sendFileNotify()
}
