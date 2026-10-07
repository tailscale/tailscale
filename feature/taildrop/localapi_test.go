// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine"
)

type progressTestHost struct {
	ipnext.Host
	sent []int64
}

func (h *progressTestHost) SendNotifyAsync(n ipn.Notify) {
	for _, f := range n.OutgoingFiles {
		h.sent = append(h.sent, f.Sent)
	}
}

// TestResumedOutgoingProgress verifies that resumed upload notifications
// include the existing prefix and never regress, including when the receiver
// already has the whole file.
func TestResumedOutgoingProgress(t *testing.T) {
	const content = "hello world"
	for _, prefix := range []string{"", "hello", content, "wrong"} {
		t.Run(fmt.Sprintf("prefix=%q", prefix), func(t *testing.T) {
			host := &progressTestHost{}
			p := newOutgoingProgress(&Extension{host: host})
			p.notifyInterval = 0
			first := true
			offset, remaining, err := resumeReader(strings.NewReader(content), func() (blockChecksum, error) {
				if !first || prefix == "" {
					return blockChecksum{}, io.EOF
				}
				first = false
				return blockChecksum{hashBlock([]byte(prefix)), hashAlgorithm, int64(len(prefix))}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			wantOffset := int64(len(prefix))
			if prefix == "wrong" {
				wantOffset = 0
			}
			if offset != wantOffset {
				t.Fatalf("resume offset = %d; want %d", offset, wantOffset)
			}
			file := ipn.OutgoingFile{ID: "transfer", Name: "file", DeclaredSize: int64(len(content))}
			data, err := io.ReadAll(p.trackReader(remaining, &file, offset))
			p.notify()
			if err != nil || string(data) != content[offset:] {
				t.Fatalf("suffix: %q, %v", data, err)
			}
			if file.Sent != int64(len(content)) {
				t.Fatalf("Sent = %d; want %d", file.Sent, len(content))
			}
			if len(host.sent) == 0 || host.sent[0] != offset {
				t.Fatalf("initial progress: %v; offset=%d", host.sent, offset)
			}
			for i := 1; i < len(host.sent); i++ {
				if host.sent[i] < host.sent[i-1] {
					t.Fatalf("regressing progress: %v", host.sent)
				}
			}
		})
	}
}

// TestMultiFileResponseLength verifies that combining per-file responses must
// not retain a single response’s Content-Length and truncate the batch response
// on the wire.
func TestMultiFileResponseLength(t *testing.T) {
	w := &multiFilePostResponseWriter{}
	for range 3 {
		w.Header().Set("Content-Length", "3")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{}\n")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(dst http.ResponseWriter, _ *http.Request) {
		if err := w.Flush(dst); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != strings.Repeat("{}\n", 3) {
		t.Fatalf("body=%q, err=%v", body, err)
	}
}

// TestMultiFilePostBatchLimit verifies that consent manifest count and byte
// limits reject oversized batches without imposing those limits on ordinary
// transfers.
func TestMultiFilePostBatchLimit(t *testing.T) {
	for _, consent := range []bool{false, true} {
		for _, count := range []int{0, 8, 9, 129, 2048} {
			t.Run(fmt.Sprintf("consent=%v/count=%d", consent, count), func(t *testing.T) {
				var body bytes.Buffer
				mw := multipart.NewWriter(&body)
				part, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
				if err != nil {
					t.Fatal(err)
				}
				manifest := make([]ipn.OutgoingFile, count)
				for i := range manifest {
					manifest[i] = ipn.OutgoingFile{ID: fmt.Sprint(i), Name: fmt.Sprintf("%d.txt", i)}
				}
				if err := json.NewEncoder(part).Encode(manifest); err != nil {
					t.Fatal(err)
				}
				if count == 2048 && body.Len() <= 128<<10 {
					t.Fatal("large batch must exceed the consent manifest byte limit")
				}
				if err := mw.Close(); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("POST", "/", &body)
				req.Header.Set("Content-Type", mw.FormDataContentType())
				w := httptest.NewRecorder()
				uid := tailcfg.UserID(1)
				if consent {
					uid = 2
				}
				progress := newOutgoingProgress(&Extension{host: &progressTestHost{}, selfUID: 1, sb: consentTestBackend{}, nodeBackendForTest: testNodeBackend{peers: []tailcfg.NodeView{(&tailcfg.Node{StableID: "peer", User: uid}).View()}}})
				multiFilePost(&localapi.Handler{}, progress, w, req, "peer", nil)
				// Admitted nonempty manifests fail because the body omits its
				// file parts. Only consent-required sends have a file-count limit.
				want := "invalid Taildrop batch size: send between 1 and 8 files per transfer"
				if count == 8 || !consent {
					want = "multipart files do not match manifest"
				}
				if consent && count == 2048 {
					want = "invalid manifest"
				}
				if !consent && count == 0 {
					if w.Code != http.StatusOK {
						t.Fatalf("empty batch status = %d", w.Code)
					}
					return
				}
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) {
					t.Fatalf("response = %d %q; want 400 %q", w.Code, w.Body.String(), want)
				}
			})
		}
	}
}

// TestSingleFilePutConsentResume verifies that a fresh approval cannot resume
// an earlier grant’s bytes, but retries of the same failed transaction reuse
// approval and upload only the remaining suffix.
func TestSingleFilePutConsentResume(t *testing.T) {
	sys := tsd.NewSystemWithBus(eventbustest.NewBus(t))
	sys.Set(new(mem.Store))
	eng, err := wgengine.NewFakeUserspaceEngine(t.Logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)
	backend, err := ipnlocal.NewLocalBackend(t.Logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Shutdown)
	handler := localapi.NewHandler(localapi.HandlerConfig{Backend: backend, Logf: t.Logf, EventBus: sys.Bus.Get()})

	const content = "hello world"
	type observedPut struct {
		rangeHeader, body, nonce string
		length                   int64
	}
	puts := make(chan observedPut, 2)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			// Before the first PUT this prefix belongs to an earlier grant.
			// After the failed PUT it belongs to this transaction.
			json.NewEncoder(w).Encode(blockChecksum{hashBlock([]byte("hello")), hashAlgorithm, 5})
		case "PUT":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			puts <- observedPut{r.Header.Get("Range"), string(body), r.Header.Get(hdrConsentNonce), r.ContentLength}
			if attempts.Add(1) == 1 {
				// Model a receiver that saved only the first five bytes.
				http.Error(w, "interrupted", http.StatusInternalServerError)
			} else {
				io.WriteString(w, "{}\n")
			}
		default:
			t.Errorf("unexpected consent renegotiation: %s", r.Method)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	dst, _ := url.Parse(srv.URL)
	ext := &Extension{host: &progressTestHost{}, sb: consentTestBackend{}, selfUID: 1,
		nodeBackendForTest: testNodeBackend{peers: []tailcfg.NodeView{(&tailcfg.Node{StableID: testPeerA, User: 2}).View()}}}
	t.Cleanup(ext.sentConsent.Clear)
	metadata := testConsentMetadata("file.txt", int64(len(content)))
	key := outboundConsentKey{Peer: testPeerA, Filename: "file.txt", Size: metadata.Size, TxID: metadata.TxID, Hash: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
	token := &ConsentToken{TxID: key.TxID, Hash: key.Hash, Token: "token", Nonce: "grant", ExpiresAt: time.Now().Add(time.Minute)}
	ext.sentConsent.store(ext.Clock().Now(), key, token)
	file := ipn.OutgoingFile{ID: key.TxID, PeerID: testPeerA, Name: key.Filename, DeclaredSize: key.Size}
	for i := range 2 {
		w := httptest.NewRecorder()
		singleFilePut(handler, context.Background(), newOutgoingProgress(ext), w, strings.NewReader(content), dst, file)
		wantStatus := http.StatusInternalServerError
		want := observedPut{"", content, token.Nonce, int64(len(content))}
		if i == 1 {
			wantStatus = http.StatusOK
			want.rangeHeader, want.body, want.length = "bytes=5-", " world", 6
		}
		if w.Code != wantStatus {
			t.Fatalf("attempt %d: status=%d body=%s", i, w.Code, w.Body)
		}
		select {
		case got := <-puts:
			if got != want {
				t.Fatalf("attempt %d: got %+v; want %+v", i, got, want)
			}
		default:
			t.Fatal("no peer PUT")
		}
		// Polling the same approval must not reset its upload history.
		if i == 0 {
			ext.sentConsent.store(ext.Clock().Now(), key, token)
		}
	}
	if ext.consentToken(key) != nil {
		t.Fatal("successful upload retained its token")
	}
}
