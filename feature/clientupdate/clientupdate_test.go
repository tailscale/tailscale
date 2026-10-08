// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package clientupdate

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/ipn/localapi"
	"tailscale.com/util/httpm"
)

// TestServeUpdateInstallRequiresWrite verifies that the update/install
// localapi handler denies requests from clients without write permission,
// i.e. non-root, non-operator local users.
func TestServeUpdateInstallRequiresWrite(t *testing.T) {
	h := &localapi.Handler{PermitWrite: false}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(httpm.POST, "/localapi/v0/update/install", nil)
	serveUpdateInstall(h, rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
