// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httpstore contains an ipn.StateStore implementation using generic HTTP.
//
// Write Request
//
// To write state to the server, the client sends a POST request
// with content type `application/vnd.tailscale.ipn-state+json`.
//
// The server is expected to return response code "204 No Content".
// It is assumed the write request has failed in case of any other response code.
//
// Read Request
//
// To read state, the client sends a simple GET request.
//
// If the server has previously received a write request against the same URL,
// it is expected to return a "200 OK" response.
// The response should carry the content type and body as described above.
//
// Otherwise, the server is expected to return "204 No Content".
//
// It is assumed the read request has failed in case of any other response code.
package httpstore

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

// httpStore is a HTTP-backed store with in-memory write-through caching.
type httpStore struct {
	httpClient *http.Client
	requestURL string
	memory     mem.Store
}

const contentType = "application/vnd.tailscale.ipn-state+json"

// New returns a new ipn.StateStore backed by the provided URL.
//
// Internally, http.DefaultTransport is used with a 5s timeout.
//
// As of Go 1.18, the http and https schemes over HTTP/1.1 or HTTP/2 are supported.
func New(_ logger.Logf, httpURL string) (ipn.StateStore, error) {
	return newStore(httpURL, nil)
}

// newStore is NewStore, but for tests.
// If client is non-nil, http.DefaultClient is used.
func newStore(httpURL string, client *http.Client) (ipn.StateStore, error) {
	s := &httpStore{
		httpClient: client,
		requestURL: httpURL,
	}

	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}

	// Hydrate cache with the potentially current state
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadState sends a read request to the server and updates local cache.
// If remote state doesn't exist, sends a write request creating empty state.
func (s *httpStore) loadState() error {
	req, err := http.NewRequest(http.MethodGet, s.requestURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("accept", contentType)

	res, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNoContent {
		return s.writeState()
	}

	const sizeLimit = 1 << 20 // 1 MiB
	bs, err := io.ReadAll(io.LimitReader(res.Body, sizeLimit))
	if err != nil {
		return err
	}
	if len(bs) == sizeLimit {
		return fmt.Errorf("rejecting too large ipn state (content length %d)", res.ContentLength)
	}

	return s.memory.LoadFromJSON(bs)
}

func (s *httpStore) String() string {
	u, err := url.Parse(s.requestURL)
	if err != nil {
		return "httpStore(<invalid URL>)"
	}
	u.User = nil
	return fmt.Sprintf("httpStore(%q)", u.String())
}

// ReadState implements the ipn.StateStore interface.
func (s *httpStore) ReadState(id ipn.StateKey) (bs []byte, err error) {
	return s.memory.ReadState(id)
}

// WriteState implements the ipn.StateStore interface.
//
// Sends a write request to the server.
func (s *httpStore) WriteState(id ipn.StateKey, bs []byte) (err error) {
	if err = s.memory.WriteState(id, bs); err != nil {
		return
	}
	return s.writeState()
}

func (s *httpStore) writeState() error {
	// Generate JSON from in-memory cache
	bs, err := s.memory.ExportToJSON()
	if err != nil {
		return err
	}

	res, err := s.httpClient.Post(s.requestURL, contentType, bytes.NewReader(bs))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected HTTP status; want=204, got=%q", res.Status)
	}
	return nil
}
