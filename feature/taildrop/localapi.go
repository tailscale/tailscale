// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/httphdr"
	"tailscale.com/util/mak"
	"tailscale.com/util/progresstracking"
	"tailscale.com/util/rands"
)

func init() {
	localapi.Register("file-put/", serveFilePut)
	localapi.Register("files/", serveFiles)
	localapi.Register("file-targets", serveFileTargets)
}

var (
	metricFilePutCalls = clientmetric.NewCounter("localapi_file_put")
)

// serveFilePut sends a file to another node.
//
// It's sometimes possible for clients to do this themselves, without
// tailscaled, except in the case of tailscaled running in
// userspace-networking ("netstack") mode, in which case tailscaled
// needs to a do a netstack dial out.
//
// Instead, the CLI also goes through tailscaled so it doesn't need to be
// aware of the network mode in use.
//
// macOS/iOS have always used this localapi method to simplify the GUI
// clients.
//
// The Windows client currently (2021-11-30) uses the peerapi (/v0/put/)
// directly, as the Windows GUI always runs in tun mode anyway.
//
// In addition to single file PUTs, this endpoint accepts multipart file
// POSTS encoded as multipart/form-data.The first part should be an
// application/json file that contains a manifest consisting of a JSON array of
// OutgoingFiles which we can use for tracking progress even before reading the
// file parts.
//
// URL format:
//
//   - PUT /localapi/v0/file-put/:stableID/:escaped-filename
//   - POST /localapi/v0/file-put/:stableID
func serveFilePut(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	metricFilePutCalls.Add(1)

	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}

	if r.Method != "PUT" && r.Method != "POST" {
		http.Error(w, "want PUT to put file", http.StatusBadRequest)
		return
	}

	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}

	fts, err := ext.FileTargets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	upath, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/file-put/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	var peerIDStr, filenameEscaped string
	if r.Method == "PUT" {
		ok := false
		peerIDStr, filenameEscaped, ok = strings.Cut(upath, "/")
		if !ok {
			http.Error(w, "bogus URL", http.StatusBadRequest)
			return
		}
	} else {
		peerIDStr = upath
	}
	peerID := tailcfg.StableNodeID(peerIDStr)

	var ft *apitype.FileTarget
	for _, x := range fts {
		if x.Node.StableID == peerID {
			ft = x
			break
		}
	}
	if ft == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}
	dstURL, err := url.Parse(ft.PeerAPIURL)
	if err != nil {
		http.Error(w, "bogus peer URL", http.StatusInternalServerError)
		return
	}

	// Periodically report progress of outgoing files.
	outgoingFiles := make(map[string]*ipn.OutgoingFile)
	t := time.NewTicker(1 * time.Second)
	progressUpdates := make(chan ipn.OutgoingFile)
	defer close(progressUpdates)

	go func() {
		defer t.Stop()
		defer ext.updateOutgoingFiles(outgoingFiles)
		for {
			select {
			case u, ok := <-progressUpdates:
				if !ok {
					return
				}
				outgoingFiles[u.ID] = &u
			case <-t.C:
				ext.updateOutgoingFiles(outgoingFiles)
			}
		}
	}()

	switch r.Method {
	case "PUT":
		file := ipn.OutgoingFile{
			ID:           rands.HexString(30),
			PeerID:       peerID,
			Name:         filenameEscaped,
			DeclaredSize: r.ContentLength,
		}
		singleFilePut(h, r.Context(), progressUpdates, w, r.Body, dstURL, file)
	case "POST":
		multiFilePost(h, progressUpdates, w, r, peerID, dstURL)
	default:
		http.Error(w, "want PUT to put file", http.StatusBadRequest)
		return
	}
}

func multiFilePost(h *localapi.Handler, progressUpdates chan (ipn.OutgoingFile), w http.ResponseWriter, r *http.Request, peerID tailcfg.StableNodeID, dstURL *url.URL) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid Content-Type for multipart POST: %s", err), http.StatusBadRequest)
		return
	}

	ww := &multiFilePostResponseWriter{}
	defer func() {
		if err := ww.Flush(w); err != nil {
			h.Logf("error: multiFilePostResponseWriter.Flush(): %s", err)
		}
	}()

	outgoingFilesByName := make(map[string]ipn.OutgoingFile)
	first := true
	mr := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			// No more parts.
			return
		} else if err != nil {
			http.Error(ww, fmt.Sprintf("failed to decode multipart/form-data: %s", err), http.StatusBadRequest)
			return
		}

		if first {
			first = false
			if part.Header.Get("Content-Type") != "application/json" {
				http.Error(ww, "first MIME part must be a JSON map of filename -> size", http.StatusBadRequest)
				return
			}

			var manifest []ipn.OutgoingFile
			err := json.NewDecoder(part).Decode(&manifest)
			if err != nil {
				http.Error(ww, fmt.Sprintf("invalid manifest: %s", err), http.StatusBadRequest)
				return
			}

			for _, file := range manifest {
				outgoingFilesByName[file.Name] = file
				progressUpdates <- file
			}

			continue
		}

		if !singleFilePut(h, r.Context(), progressUpdates, ww, part, dstURL, outgoingFilesByName[part.FileName()]) {
			return
		}

		if ww.statusCode >= 400 {
			// put failed, stop immediately
			h.Logf("error: singleFilePut: failed with status %d", ww.statusCode)
			return
		}
	}
}

// multiFilePostResponseWriter is a buffering http.ResponseWriter that can be
// reused across multiple singleFilePut calls and then flushed to the client
// when all files have been PUT.
type multiFilePostResponseWriter struct {
	header     http.Header
	statusCode int
	body       *bytes.Buffer
}

func (ww *multiFilePostResponseWriter) Header() http.Header {
	if ww.header == nil {
		ww.header = make(http.Header)
	}
	return ww.header
}

func (ww *multiFilePostResponseWriter) WriteHeader(statusCode int) {
	ww.statusCode = statusCode
}

func (ww *multiFilePostResponseWriter) Write(p []byte) (int, error) {
	if ww.body == nil {
		ww.body = bytes.NewBuffer(nil)
	}
	return ww.body.Write(p)
}

func (ww *multiFilePostResponseWriter) Flush(w http.ResponseWriter) error {
	if ww.header != nil {
		maps.Copy(w.Header(), ww.header)
	}
	if ww.statusCode > 0 {
		w.WriteHeader(ww.statusCode)
	}
	if ww.body != nil {
		_, err := io.Copy(w, ww.body)
		return err
	}
	return nil
}

func singleFilePut(
	h *localapi.Handler,
	ctx context.Context,
	progressUpdates chan (ipn.OutgoingFile),
	w http.ResponseWriter,
	body io.Reader,
	dstURL *url.URL,
	outgoingFile ipn.OutgoingFile,
) bool {
	outgoingFile.Started = time.Now()
	body = progresstracking.NewReader(body, 1*time.Second, func(n int, err error) {
		outgoingFile.Sent = int64(n)
		progressUpdates <- outgoingFile
	})

	fail := func() {
		outgoingFile.Finished = true
		outgoingFile.Succeeded = false
		progressUpdates <- outgoingFile
	}

	// Before we PUT a file we check to see if there are any existing partial file and if so,
	// we resume the upload from where we left off by sending the remaining file instead of
	// the full file.
	var offset int64
	var resumeDuration time.Duration
	remainingBody := io.Reader(body)
	client := &http.Client{
		Transport: h.LocalBackend().Dialer().PeerAPITransport(),
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", dstURL.String()+"/v0/put/"+outgoingFile.Name, nil)
	if err != nil {
		http.Error(w, "bogus peer URL", http.StatusInternalServerError)
		fail()
		return false
	}
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	switch {
	case err != nil:
		h.Logf("could not fetch remote hashes: %v", err)
	case resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound:
		// noop; implies older peerapi without resume support
	case resp.StatusCode != http.StatusOK:
		h.Logf("fetch remote hashes status code: %d", resp.StatusCode)
	default:
		resumeStart := time.Now()
		dec := json.NewDecoder(resp.Body)
		offset, remainingBody, err = resumeReader(body, func() (out blockChecksum, err error) {
			err = dec.Decode(&out)
			return out, err
		})
		if err != nil {
			h.Logf("reader could not be fully resumed: %v", err)
		}
		resumeDuration = time.Since(resumeStart).Round(time.Millisecond)
	}

	outReq, err := http.NewRequestWithContext(ctx, "PUT", "http://peer/v0/put/"+outgoingFile.Name, remainingBody)
	if err != nil {
		http.Error(w, "bogus outreq", http.StatusInternalServerError)
		fail()
		return false
	}
	outReq.ContentLength = outgoingFile.DeclaredSize
	if offset > 0 {
		h.Logf("resuming put at offset %d after %v", offset, resumeDuration)
		rangeHdr, _ := httphdr.FormatRange([]httphdr.Range{{Start: offset, Length: 0}})
		outReq.Header.Set("Range", rangeHdr)
		if outReq.ContentLength >= 0 {
			outReq.ContentLength -= offset
		}
	}

	rp := httputil.NewSingleHostReverseProxy(dstURL)
	rp.Transport = h.LocalBackend().Dialer().PeerAPITransport()
	rp.ServeHTTP(w, outReq)

	outgoingFile.Finished = true
	outgoingFile.Succeeded = true
	progressUpdates <- outgoingFile

	return true
}

func serveFiles(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}

	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}

	suffix, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/files/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	if suffix == "" {
		if r.Method != "GET" {
			http.Error(w, "want GET to list files", http.StatusBadRequest)
			return
		}
		ctx := r.Context()
		var wfs []apitype.WaitingFile
		if s := r.FormValue("waitsec"); s != "" && s != "0" {
			d, err := strconv.Atoi(s)
			if err != nil {
				http.Error(w, "invalid waitsec", http.StatusBadRequest)
				return
			}
			deadline := time.Now().Add(time.Duration(d) * time.Second)
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
			wfs, err = ext.AwaitWaitingFiles(ctx)
			if err != nil && ctx.Err() == nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			var err error
			wfs, err = ext.WaitingFiles()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wfs)
		return
	}
	name, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad filename", http.StatusBadRequest)
		return
	}
	if r.Method == "DELETE" {
		if err := ext.DeleteFile(name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc, size, err := ext.OpenFile(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, rc)
}

func serveFileTargets(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "want GET to list targets", http.StatusBadRequest)
		return
	}

	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}

	fts, err := ext.FileTargets()
	if err != nil {
		localapi.WriteErrorJSON(w, err)
		return
	}
	mak.NonNilSliceForJSON(&fts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fts)
}
