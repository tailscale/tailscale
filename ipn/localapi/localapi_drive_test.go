// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package localapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServeSharesNotEnabled checks that the shares handler doesn't return
// 403 when the node lacks the drive:share attribute. The CLI reads a 403
// as a local permission problem and suggests sudo, which can't help here.
// See https://github.com/tailscale/tailscale/issues/22502.
func TestServeSharesNotEnabled(t *testing.T) {
	h := handlerForTest(t, &Handler{
		PermitRead:  true,
		PermitWrite: true,
		b:           newTestLocalBackend(t),
	})
	rec := httptest.NewRecorder()
	h.serveShares(rec, httptest.NewRequest("GET", "/v0/drive/shares", nil))
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want %d; body=%q", rec.Code, http.StatusPreconditionFailed, rec.Body.String())
	}
}
