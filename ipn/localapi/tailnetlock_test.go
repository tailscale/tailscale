// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package localapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServeTKAInitNotAllowed checks that Tailnet Lock init doesn't return
// 403 when the tailnet's plan doesn't support Tailnet Lock. The CLI reads a
// 403 as a local permission problem and suggests sudo, which can't help
// here. See https://github.com/tailscale/tailscale/issues/22502.
func TestServeTKAInitNotAllowed(t *testing.T) {
	h := handlerForTest(t, &Handler{
		PermitRead:  true,
		PermitWrite: true,
		b:           newTestLocalBackend(t),
	})
	rec := httptest.NewRecorder()
	h.serveTKAInit(rec, httptest.NewRequest("POST", "/v0/tka/init", strings.NewReader("{}")))
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusPreconditionFailed, rec.Body.String())
	}
}
