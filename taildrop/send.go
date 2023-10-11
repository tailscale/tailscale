// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tstime"
	"tailscale.com/version/distro"
)

type incomingFile struct {
	clock tstime.Clock

	name           string // "foo.jpg"
	started        time.Time
	size           int64     // or -1 if unknown; never 0
	w              io.Writer // underlying writer
	sendFileNotify func()    // called when done
	partialPath    string    // non-empty in direct mode

	mu         sync.Mutex
	copied     int64
	done       bool
	lastNotify time.Time
}

func (f *incomingFile) markAndNotifyDone() {
	f.mu.Lock()
	f.done = true
	f.mu.Unlock()
	f.sendFileNotify()
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

// HandlePut receives a file.
// It handles an HTTP PUT request to the "/v0/put/{filename}" endpoint,
// where {filename} is a base filename.
// It returns the number of bytes received and whether it was received successfully.
func (h *Handler) HandlePut(w http.ResponseWriter, r *http.Request) (finalSize int64, success bool) {
	if !envknob.CanTaildrop() {
		http.Error(w, "Taildrop disabled on device", http.StatusForbidden)
		return finalSize, success
	}
	if r.Method != "PUT" {
		http.Error(w, "expected method PUT", http.StatusMethodNotAllowed)
		return finalSize, success
	}
	if h == nil || h.Dir == "" {
		http.Error(w, errNoTaildrop.Error(), http.StatusInternalServerError)
		return finalSize, success
	}
	if distro.Get() == distro.Unraid && !h.DirectFileMode {
		http.Error(w, "Taildrop folder not configured or accessible", http.StatusInternalServerError)
		return finalSize, success
	}
	rawPath := r.URL.EscapedPath()
	suffix, ok := strings.CutPrefix(rawPath, "/v0/put/")
	if !ok {
		http.Error(w, "misconfigured internals", http.StatusInternalServerError)
		return finalSize, success
	}
	if suffix == "" {
		http.Error(w, "empty filename", http.StatusBadRequest)
		return finalSize, success
	}
	if strings.Contains(suffix, "/") {
		http.Error(w, "directories not supported", http.StatusBadRequest)
		return finalSize, success
	}
	baseName, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad path encoding", http.StatusBadRequest)
		return finalSize, success
	}
	dstFile, ok := h.diskPath(baseName)
	if !ok {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return finalSize, success
	}
	// TODO(bradfitz): prevent same filename being sent by two peers at once

	// prevent same filename being sent twice
	if _, err := os.Stat(dstFile); err == nil {
		http.Error(w, "file exists", http.StatusConflict)
		return finalSize, success
	}

	partialFile := dstFile + partialSuffix
	f, err := os.Create(partialFile)
	if err != nil {
		h.Logf("put Create error: %v", redactErr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return finalSize, success
	}
	defer func() {
		if !success {
			os.Remove(partialFile)
		}
	}()
	var inFile *incomingFile
	sendFileNotify := h.SendFileNotify
	if sendFileNotify == nil {
		sendFileNotify = func() {} // avoid nil panics below
	}
	if r.ContentLength != 0 {
		inFile = &incomingFile{
			clock:          h.Clock,
			name:           baseName,
			started:        h.Clock.Now(),
			size:           r.ContentLength,
			w:              f,
			sendFileNotify: sendFileNotify,
		}
		if h.DirectFileMode {
			inFile.partialPath = partialFile
		}
		h.incomingFiles.Store(inFile, struct{}{})
		defer h.incomingFiles.Delete(inFile)
		n, err := io.Copy(inFile, r.Body)
		if err != nil {
			err = redactErr(err)
			f.Close()
			h.Logf("put Copy error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return finalSize, success
		}
		finalSize = n
	}
	if err := redactErr(f.Close()); err != nil {
		h.Logf("put Close error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return finalSize, success
	}
	if h.DirectFileMode && h.AvoidFinalRename {
		if inFile != nil { // non-zero length; TODO: notify even for zero length
			inFile.markAndNotifyDone()
		}
	} else {
		if err := os.Rename(partialFile, dstFile); err != nil {
			err = redactErr(err)
			h.Logf("put final rename: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return finalSize, success
		}
	}

	// TODO: set modtime
	// TODO: some real response
	success = true
	io.WriteString(w, "{}\n")
	h.knownEmpty.Store(false)
	sendFileNotify()
	return finalSize, success
}
