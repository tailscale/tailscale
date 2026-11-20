// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/util/httpm"
)

func TestServeDebugDialTypes(t *testing.T) {
	b := newTestLocalBackend(t)
	if b.Dialer().PeerDialControlFunc() != nil {
		t.Skip("requires an initialized peer interface in an Apple extension")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"ip": {host}, "port": {port}, "network": {"tcp4"}}
	req := httptest.NewRequest(httpm.POST, "/debug-dial-types", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h := &Handler{b: b, PermitWrite: true}
	h.serveDebugDialTypes(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	for _, name := range []string{"SystemDial", "UserDial", "PeerDial", "BareDial"} {
		want := "[" + name + "] connected=true err=<nil>"
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("missing successful %s result in %q", name, w.Body.String())
		}
	}
}
