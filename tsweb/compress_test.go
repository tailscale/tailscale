// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestCompressingHandler(t *testing.T) {
	h := compressingHandler{nil}
	var _ http.Handler = h

	w := &compressingResponseWriter{}
	var (
		_ http.ResponseWriter = w
		_ http.Flusher        = w
		_ http.Hijacker       = w
	)

	// testRequest constructs a response recorder and a compressing handler that
	// wraps the given handler h, it calls the handler with r, and returns the
	// response recorder. If r is nil, then a GET request is made to "/" with no
	// additional headers.
	testRequest := func(r *http.Request, h http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		if r == nil {
			r = httptest.NewRequest("GET", "/", nil)
		}
		compressingHandler{h}.ServeHTTP(w, r)
		return w
	}

	checkBody := func(r io.Reader, want string) {
		t.Helper()
		body, err := ioutil.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want {
			t.Errorf("got body %q, want %q", body, want)
		}
	}

	checkHeader := func(h http.Header, key, want string) {
		t.Helper()
		if got := h.Get(key); got != want {
			t.Errorf("got header %q=%q, want %q", key, got, want)
		}
	}

	t.Run("transparently compresses content with brotli", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", "br")

		w := testRequest(r, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello world"))
		})

		checkHeader(w.Header(), "Content-Encoding", "br")
		checkBody(brotli.NewReader(w.Body), "hello world")
	})

	t.Run("transparently compresses content with gzip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", "gzip")

		w := testRequest(r, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello world"))
		})

		checkHeader(w.Header(), "Content-Encoding", "gzip")
		br, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		checkBody(br, "hello world")
	})

	t.Run("does not compress content if client does not accept compressed content", func(t *testing.T) {
		w := testRequest(nil, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello world"))
		})

		checkHeader(w.Header(), "Content-Encoding", "")
		checkBody(w.Body, "hello world")
	})

	t.Run("does not recompress content if client accepts compressed content but content is already compressed", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", "br")

		w := testRequest(r, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "magic")
			w.Write([]byte("hello world"))
		})

		checkHeader(w.Header(), "Content-Encoding", "magic")
		checkBody(w.Body, "hello world")
	})

	t.Run("integration", func(t *testing.T) {
		s := httptest.NewServer(compressingHandler{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello world"))
		})})
		defer s.Close()

		r, err := http.NewRequest("GET", s.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Accept-Encoding", "gzip")
		res, err := s.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}

		checkHeader(res.Header, "Content-Encoding", "gzip")
		br, err := gzip.NewReader(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		checkBody(br, "hello world")
	})

}
