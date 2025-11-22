// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package ipnlocal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDriveTransportRoundTrip_NetworkError tests that driveTransport.RoundTrip
// doesn't panic when the underlying transport returns a nil response with an
// error.
//
// See: https://github.com/tailscale/tailscale/issues/17306
func TestDriveTransportRoundTrip_NetworkError(t *testing.T) {
	b := newTestLocalBackend(t)

	testErr := errors.New("network connection failed")
	mockTransport := &mockRoundTripper{
		err: testErr,
	}
	dt := &driveTransport{
		b:  b,
		tr: mockTransport,
	}

	req := httptest.NewRequest("GET", "http://100.64.0.1:1234/some/path", nil)
	resp, err := dt.RoundTrip(req)
	if err == nil {
		t.Fatal("got nil error, expected non-nil")
	} else if !errors.Is(err, testErr) {
		t.Errorf("got error %v, expected %v", err, testErr)
	}
	if resp != nil {
		t.Errorf("wanted nil response, got %v", resp)
	}
}

type mockRoundTripper struct {
	err error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, m.err
}
