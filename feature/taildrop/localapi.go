// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

var (
	metricFilePutCalls        = clientmetric.NewCounter("localapi_file_put")
	metricFilePutRequestCalls = clientmetric.NewCounter("localapi_file_put_request")
)

const maxConsentBatchFiles = 8

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
	if err := ext.checkSendPolicy(peerID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

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

	// Notify any updates buffered at request return.
	progress := newOutgoingProgress(ext)
	defer progress.notify()

	switch r.Method {
	case "PUT":
		file := ipn.OutgoingFile{
			ID:           rands.HexString(30),
			PeerID:       peerID,
			Name:         filenameEscaped,
			DeclaredSize: r.ContentLength,
		}
		if txid := r.Header.Get(hdrConsentTxID); txid != "" {
			file.ID = txid
		}
		singleFilePut(h, r.Context(), progress, w, r.Body, dstURL, file)
	case "POST":
		multiFilePost(h, progress, w, r, peerID, dstURL)
	default:
		http.Error(w, "want PUT to put file", http.StatusBadRequest)
		return
	}
}

// outgoingProgress forwards file-put progress to the Taildrop Extension
// for one localapi request. update coalesces hot-path changes; notify
// distributes any pending updates to observers immediately, disregarding
// the coalescing interval. The owner must call notify before returning
// so buffered updates aren't lost.
//
// outgoingProgress is safe for concurrent use.
type outgoingProgress struct {
	ext            *Extension
	notifyInterval time.Duration

	mu      sync.Mutex
	pending map[string]ipn.OutgoingFile // by OutgoingFile.ID
	last    time.Time
}

func newOutgoingProgress(ext *Extension) *outgoingProgress {
	return &outgoingProgress{
		ext:            ext,
		notifyInterval: time.Second,
	}
}

// update buffers f. If notifyInterval has elapsed since the last notify,
// pending updates are also distributed to observers.
func (p *outgoingProgress) update(f ipn.OutgoingFile) {
	var updates map[string]ipn.OutgoingFile
	p.mu.Lock()
	mak.Set(&p.pending, f.ID, f)
	if time.Since(p.last) >= p.notifyInterval {
		updates, p.pending = p.pending, nil
		p.last = time.Now()
	}
	p.mu.Unlock()
	if updates != nil {
		p.ext.updateOutgoingFiles(updates)
	}
}

// notify distributes any pending updates to observers immediately,
// disregarding the coalescing interval. Callers should notify
// explicitly for new files and completion events so observers don't
// have to wait for the next coalesced send. It is safe to call
// repeatedly.
func (p *outgoingProgress) notify() {
	var updates map[string]ipn.OutgoingFile
	p.mu.Lock()
	if len(p.pending) > 0 {
		updates, p.pending = p.pending, nil
		p.last = time.Now()
	}
	p.mu.Unlock()
	if updates != nil {
		p.ext.updateOutgoingFiles(updates)
	}
}

// trackReader includes the already verified prefix in completion progress.
// Publish it even when the peer already has the whole file and no body is sent.
func (p *outgoingProgress) trackReader(body io.Reader, file *ipn.OutgoingFile, offset int64) io.Reader {
	file.Sent = offset
	p.update(*file)
	p.notify()
	return progresstracking.NewReader(body, time.Second, func(n int, err error) {
		file.Sent = offset + int64(n)
		p.update(*file)
	})
}

func multiFilePost(h *localapi.Handler, progress *outgoingProgress, w http.ResponseWriter, r *http.Request, peerID tailcfg.StableNodeID, dstURL *url.URL) {
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
	completed := make(map[string]bool)
	defer func() {
		for _, f := range outgoingFilesByName {
			if !completed[f.ID] {
				f.Finished = true
				f.CompletedAt = time.Now()
				f.Succeeded = false
				f.WaitingForConsent = false
				progress.update(f)
			}
		}
		progress.notify()
	}()
	first := true
	mr := multipart.NewReader(r.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			if first || len(completed) != len(outgoingFilesByName) {
				http.Error(ww, "multipart files do not match manifest", http.StatusBadRequest)
			}
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

			// Preserve the legacy batch size for ordinary transfers. Both
			// manifest limits belong only to the consent flow.
			needsConsent := progress.ext.shouldRequestConsent(peerID)
			var manifestReader io.Reader = part
			if needsConsent {
				manifestReader = io.LimitReader(part, 128<<10)
			}
			var manifest []ipn.OutgoingFile
			err := json.NewDecoder(manifestReader).Decode(&manifest)
			if err != nil {
				http.Error(ww, fmt.Sprintf("invalid manifest: %s", err), http.StatusBadRequest)
				return
			}
			if needsConsent && (len(manifest) == 0 || len(manifest) > maxConsentBatchFiles) {
				http.Error(ww, fmt.Sprintf("invalid Taildrop batch size: send between 1 and %d files per transfer", maxConsentBatchFiles), http.StatusBadRequest)
				return
			}

			ids := make(map[string]bool)
			for _, file := range manifest {
				// The manifest comes from the client and needn't name the
				// peer, but downstream consumers key on it.
				file.PeerID = peerID
				if _, exists := outgoingFilesByName[file.Name]; exists {
					http.Error(ww, "duplicate filename in manifest", http.StatusBadRequest)
					return
				}
				if file.ID == "" {
					file.ID = rands.HexString(32)
				}
				if ids[file.ID] {
					http.Error(ww, "duplicate transaction ID in manifest", http.StatusBadRequest)
					return
				}
				ids[file.ID] = true
				outgoingFilesByName[file.Name] = file
				progress.update(file)
			}

			continue
		}
		file, ok := outgoingFilesByName[part.FileName()]
		if !ok {
			http.Error(ww, "file absent from manifest", http.StatusBadRequest)
			return
		}
		if completed[file.ID] {
			http.Error(ww, "duplicate file part", http.StatusBadRequest)
			return
		}

		// Keep each file's response separate: a decline must neither abort
		// later files nor have its failure hidden by a later success.
		fileResponse := &multiFilePostResponseWriter{}
		ok = singleFilePut(h, r.Context(), progress, fileResponse, part, dstURL, file)
		completed[file.ID] = true
		declined := fileResponse.statusCode == http.StatusForbidden && fileResponse.Header().Get(hdrConsentError) == ErrConsentDenied.Error()
		if declined {
			name, _ := url.PathUnescape(file.Name)
			fileResponse.body = bytes.NewBufferString(fmt.Sprintf("%q: %s\n", name, ErrConsentDenied))
		}
		if fileResponse.statusCode >= 400 && ww.statusCode < 400 {
			// Once any file fails, return only failure details to the client.
			*ww = multiFilePostResponseWriter{}
		}
		if ww.statusCode < 400 || fileResponse.statusCode >= 400 {
			if err := fileResponse.Flush(ww); err != nil {
				h.Logf("error buffering file response: %v", err)
				return
			}
		}
		if declined {
			continue
		}
		if !ok {
			return
		}

		if fileResponse.statusCode >= 400 {
			// put failed, stop immediately
			h.Logf("error: singleFilePut: failed with status %d", fileResponse.statusCode)
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
	// Each proxied response describes only one file. The buffered response
	// contains all of them, so its length must be computed independently.
	w.Header().Del("Content-Length")
	if ww.statusCode > 0 {
		w.WriteHeader(ww.statusCode)
	}
	if ww.body != nil {
		_, err := io.Copy(w, ww.body)
		return err
	}
	return nil
}

// consentAwareWriter notes whether the peer refused the request on consent
// grounds, so a plain 403 (not authorized) or 409 (file already exists) isn't
// mistaken for one. The reverse proxy writes straight through to the client, so
// this only observes.
type consentAwareWriter struct {
	http.ResponseWriter
	consentRejected bool
	status          int
}

func (w *consentAwareWriter) WriteHeader(status int) {
	w.status = status
	w.consentRejected = w.Header().Get(hdrConsentError) != ""
	w.ResponseWriter.WriteHeader(status)
}

// createSendTemp stages outgoing files under the backend's writable storage
// area, since sandboxed Apple extensions may not have access to os.TempDir().
// Without a storage area, it uses the system temporary directory.
func createSendTemp(root string) (*os.File, error) {
	var dir string
	if root != "" {
		dir = filepath.Join(root, "tmp")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	return os.CreateTemp(dir, "tailscale-taildrop-send-*")
}

// stagedSend holds the exact bytes committed to by a consent request.
type stagedSend struct {
	*os.File
	metadata PutRequest
}

func (s *stagedSend) Close() error {
	err := s.File.Close()
	removeErr := os.Remove(s.Name())
	if err != nil {
		return err
	}
	return removeErr
}

func stageSendFile(root string, body io.Reader, outgoing ipn.OutgoingFile) (_ *stagedSend, err error) {
	name, err := url.PathUnescape(outgoing.Name)
	if err != nil {
		return nil, err
	}
	if err := validateBaseName(name); err != nil {
		return nil, err
	}
	f, err := createSendTemp(root)
	if err != nil {
		return nil, err
	}
	s := &stagedSend{File: f}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(f, hash), body)
	if err != nil {
		return nil, err
	}
	if outgoing.DeclaredSize >= 0 && outgoing.DeclaredSize != size {
		return nil, fmt.Errorf("file size does not match metadata")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if outgoing.ID == "" {
		outgoing.ID = rands.HexString(32)
	}
	s.metadata = PutRequest{Size: size, TxID: outgoing.ID, Hash: hex.EncodeToString(hash.Sum(nil))}
	return s, nil
}

func singleFilePut(
	h *localapi.Handler,
	ctx context.Context,
	progress *outgoingProgress,
	w http.ResponseWriter,
	body io.Reader,
	dstURL *url.URL,
	outgoingFile ipn.OutgoingFile,
) bool {
	outgoingFile.Started = time.Now()
	outgoingFile.CompletedAt = time.Time{}
	outgoingFile.Finished = false
	outgoingFile.Succeeded = false
	outgoingFile.Declined = false
	progress.update(outgoingFile)
	progress.notify()

	fail := func() {
		outgoingFile.WaitingForConsent = false
		outgoingFile.Finished = true
		outgoingFile.CompletedAt = time.Now()
		outgoingFile.Succeeded = false
		progress.update(outgoingFile)
		progress.notify()
	}

	transport := h.LocalBackend().Dialer().PeerAPITransport()

	ext := progress.ext
	var consent *ConsentToken
	var consentKey outboundConsentKey
	// Preserve normal same-user sends, unless the consent testing override is enabled.
	if ext.shouldRequestConsent(outgoingFile.PeerID) {
		// Stage locally to commit to the exact bytes before requesting consent.
		// This also supports non-seekable streams and unknown-length LocalAPI PUTs.
		staged, err := stageSendFile(h.LocalBackend().TailscaleVarRoot(), body, outgoingFile)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			fail()
			return false
		}
		defer staged.Close()
		body = staged
		outgoingFile.DeclaredSize = staged.metadata.Size
		outgoingFile.ID = staged.metadata.TxID
		metadata := staged.metadata
		size := metadata.Size
		consentKey = outboundConsentKey{Peer: outgoingFile.PeerID, Filename: outgoingFile.Name, Size: size, TxID: metadata.TxID, Hash: metadata.Hash}
		consent = ext.consentToken(consentKey)
		if consent == nil && ext.peerRequiresConsent(outgoingFile.PeerID) {
			state, err := ext.awaitSendConsent(ctx, transport, dstURL, outgoingFile.PeerID, outgoingFile.Name, metadata, func() {
				outgoingFile.WaitingForConsent = true
				progress.update(outgoingFile)
				progress.notify()
			})
			switch {
			case err != nil:
				http.Error(w, err.Error(), http.StatusBadGateway)
				fail()
				return false
			case state == ConsentNotAllowed:
				http.Error(w, ErrConsentNotAllowed.Error(), http.StatusForbidden)
				fail()
				return false
			case state == ConsentDenied:
				outgoingFile.Declined = true
				w.Header().Set(hdrConsentError, ErrConsentDenied.Error())
				http.Error(w, ErrConsentDenied.Error(), http.StatusForbidden)
				fail()
				return false
			case state == ConsentPending:
				http.Error(w, "taildrop: timed out waiting for the peer to approve the transfer", http.StatusRequestTimeout)
				fail()
				return false
			case state == ConsentApproved:
				consent = ext.consentToken(consentKey)
			}
			outgoingFile.WaitingForConsent = false
			progress.update(outgoingFile)
			progress.notify()
		}

	}

	// Before we PUT a file we check to see if there are any existing partial file and if so,
	// we resume the upload from where we left off by sending the remaining file instead of
	// the full file.
	resumeConsent := consent != nil && ext.sentConsent.canResume(consentKey, consent)
	var offset int64
	var resumeDuration time.Duration
	remainingBody := io.Reader(body)
	client := &http.Client{
		Transport: transport,
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
	case consent != nil && !resumeConsent:
		// A new grant cannot resume bytes received under a prior grant.
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

	remainingBody = progress.trackReader(remainingBody, &outgoingFile, offset)
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
	if outReq.ContentLength == 0 {
		outReq.Body = http.NoBody
	}
	if consent != nil {
		outReq.Header.Set(hdrConsentTxID, consent.TxID)
		outReq.Header.Set(hdrConsentToken, consent.Token)
		outReq.Header.Set(hdrConsentNonce, consent.Nonce)
		outReq.Header.Set(hdrConsentExpires, consent.ExpiresAt.Format(time.RFC3339))
	}

	rp := httputil.NewSingleHostReverseProxy(dstURL)
	rp.Transport = transport
	rw := &consentAwareWriter{ResponseWriter: w}
	if consent != nil {
		ext.sentConsent.start(consentKey, consent)
	}
	rp.ServeHTTP(rw, outReq)
	if rw.consentRejected {
		// Either the peer wouldn't take the token we had, or it now wants
		// consent when we last heard it didn't. Both mean our cached view of
		// this peer is stale, so drop it and let a retry renegotiate.
		ext.forgetConsentToken(consentKey)
	}

	outgoingFile.Finished = true
	outgoingFile.CompletedAt = time.Now()
	outgoingFile.Declined = rw.status == http.StatusForbidden && rw.Header().Get(hdrConsentError) == ErrConsentDenied.Error()
	outgoingFile.Succeeded = rw.status >= 200 && rw.status < 300
	if outgoingFile.Succeeded {
		if outgoingFile.DeclaredSize >= 0 {
			outgoingFile.Sent = outgoingFile.DeclaredSize
		}
		ext.sentConsent.Delete(consentKey)
	}
	progress.update(outgoingFile)
	progress.notify()

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

// FilePutRequestStatus is the JSON response from
// POST /localapi/v0/file-put-request/:stableID/:escaped-filename.
type FilePutRequestStatus struct {
	State ConsentState `json:"state"`

	// RetryAfterMs, when State is [ConsentPending], is how long the client
	// should wait before asking again.
	RetryAfterMs int `json:"retryAfterMs,omitzero"`
}

// serveFilePutRequest asks a peer for consent to send it a file, without
// sending the file.
//
// It performs a single round trip and returns immediately, so the caller
// chooses its own polling cadence and can show a "waiting for approval" state
// rather than sitting on a stalled upload. On approval the token is cached, so
// a subsequent file-put with the same transaction ID, peer, filename, size,
// and hash sends without asking again. For a single PUT, pass the transaction
// ID in X-Taildrop-Txid; for multipart POSTs use the manifest file ID. Each new
// send must use a new transaction ID, even when sending identical contents.
//
// Calling this is optional: file-put negotiates consent by itself if no token
// has been cached. It exists so GUI clients can separate "waiting for the other
// side" from "transferring".
//
// URL format:
//
//   - POST /localapi/v0/file-put-request/:stableID/:escaped-filename
//
// The body is a [PutRequest]; the response is a [FilePutRequestStatus].
func serveFilePutRequest(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	metricFilePutRequestCalls.Add(1)

	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST to request consent", http.StatusMethodNotAllowed)
		return
	}

	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}

	upath, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/file-put-request/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	peerIDStr, filenameEscaped, ok := strings.Cut(upath, "/")
	if !ok || filenameEscaped == "" {
		http.Error(w, "bogus URL", http.StatusBadRequest)
		return
	}
	peerID := tailcfg.StableNodeID(peerIDStr)
	if err := ext.checkSendPolicy(peerID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req PutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid PutRequest JSON", http.StatusBadRequest)
		return
	}

	dstURL, err := ext.peerAPIURLFor(peerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if !ext.shouldRequestConsent(peerID) {
		writeJSON(w, FilePutRequestStatus{State: ConsentNotRequired})
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Already approved and cached; no need to bother the peer.
	key := outboundConsentKey{Peer: peerID, Filename: filenameEscaped, Size: req.Size, TxID: req.TxID, Hash: req.Hash}
	if ext.consentToken(key) != nil {
		writeJSON(w, FilePutRequestStatus{State: ConsentApproved})
		return
	}

	state, err := ext.requestSendConsent(r.Context(), h.LocalBackend().Dialer().PeerAPITransport(), dstURL, peerID, filenameEscaped, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	status := FilePutRequestStatus{State: state}
	if state == ConsentPending {
		status.RetryAfterMs = int(senderConsentPoll / time.Millisecond)
	}
	writeJSON(w, status)
}

// serveConsentPending lists the inbound transfers awaiting this device owner's
// approval.
//
// GET /localapi/v0/taildrop-consent/pending
func serveConsentPending(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "want GET to list pending consent requests", http.StatusMethodNotAllowed)
		return
	}
	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}
	writeJSON(w, ext.ConsentRequests())
}

// ConsentResponse is the JSON body of
// POST /localapi/v0/taildrop-consent/respond.
type ConsentResponse struct {
	// ID is the [tailscale.com/feature/taildrop/taildroptype.ConsentRequest.RequestID] being decided.
	ID string `json:"id"`

	// Allow is the device owner's decision.
	Allow bool `json:"allow"`
}

// serveConsentRespond records the device owner's decision on a pending inbound
// transfer.
//
// POST /localapi/v0/taildrop-consent/respond
func serveConsentRespond(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "want POST to respond to a consent request", http.StatusMethodNotAllowed)
		return
	}
	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured taildrop extension", http.StatusInternalServerError)
		return
	}

	var resp ConsentResponse
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&resp); err != nil {
		http.Error(w, "invalid ConsentResponse JSON", http.StatusBadRequest)
		return
	}
	if resp.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	switch err := ext.RespondToConsent(resp.ID, resp.Allow); err {
	case errExternalTaildropPolicy, ErrConsentNotAllowed:
		http.Error(w, err.Error(), http.StatusForbidden)
	case nil:
		w.WriteHeader(http.StatusNoContent)
	case ErrConsentUnknown:
		// Expired or already gone: the prompt the user acted on is stale.
		http.Error(w, err.Error(), http.StatusNotFound)
	case ErrConsentConsumed:
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
