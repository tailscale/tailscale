// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

func TestConnectNon101ResponseBodyBounded(t *testing.T) {
	const (
		serverResponseBodySize = 1 << 20

		// The error wraps the %q-quoted body in a fixed prefix: caller, target URL,
		// and HTTP status. That's 102 bytes for an IPv4 loopback URL with a 5-digit
		// ephemeral port; an [::1] fallback or a shorter port only shrink it, so 102
		// is an upper bound.
		maxErrPrefixLen = 102
		maxWantLen      = maxErrBodyBytes + maxErrPrefixLen
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write far more than the client's cap, to test that it bounds the read.
		w.Write(bytes.Repeat([]byte("A"), serverResponseBodySize))
	}))
	defer srv.Close()

	c, err := NewClient(key.NewNode(), srv.URL+"/derp", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect succeeded against a server that never sent 101; want error")
	}
	msg := err.Error()

	msgLen := len(msg)
	if msgLen > maxWantLen {
		t.Errorf("error string is %d bytes (server sent a %d byte body); want <= %d. "+
			"Is the io.LimitReader around the response body still there?",
			msgLen, serverResponseBodySize, maxWantLen)
	}
	// The server sends far more than the cap, so a short message means the read was truncated too aggressively.
	if msgLen < maxErrBodyBytes {
		t.Errorf("error string is too short: %d bytes; want >= %d", msgLen, maxErrBodyBytes)
	}
	if !strings.Contains(msg, "400 Bad Request") {
		t.Errorf("error %q does not include the HTTP status", msg)
	}
}
