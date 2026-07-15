// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"testing"

	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestLogAuthCachePutAndToken(t *testing.T) {
	c := &logAuthCache{logf: t.Logf}
	authID := formatAuthID(2)
	const tok = "test-jwt-token"
	c.storeToken(authID, tok)
	if got := c.loadToken(authID); got != tok {
		t.Errorf("token = %q; want %q", got, tok)
	}
	if got := c.loadToken("missing"); got != "" {
		t.Errorf("missing authID token = %q; want empty", got)
	}
}

func TestUpdateLogUploadAuth(t *testing.T) {
	lg := logtail.NewLogger(logtail.Config{
		BaseURL: "http://127.0.0.1:1", // never dialed; we only check SetAuthID
		HTTPC:   nil,
	}, t.Logf)
	// Immediately shut down the upload goroutine to avoid noise.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = lg.Shutdown(ctx)

	b := &LocalBackend{
		logf:        t.Logf,
		logUploader: lg,
		logAuth:     logAuthCache{logf: t.Logf},
	}

	const tok = "eyJ.test.jwt"
	node := &tailcfg.Node{
		ID: 42,
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrLogUploadAuth: {tailcfg.RawMessage(`"` + tok + `"`)},
		},
	}
	nm := &netmap.NetworkMap{
		SelfNode: node.View(),
	}
	b.updateLogUploadAuth(nm)
	wantID := formatAuthID(42)
	if got := b.logAuth.loadToken(wantID); got != tok {
		t.Errorf("cached token = %q; want %q", got, tok)
	}

	// A later netmap can push a refreshed token for the same auth ID.
	const tok2 = "eyJ.refreshed.jwt"
	node2 := &tailcfg.Node{
		ID: 42,
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrLogUploadAuth: {tailcfg.RawMessage(`"` + tok2 + `"`)},
		},
	}
	nm2 := &netmap.NetworkMap{
		SelfNode: node2.View(),
	}
	b.updateLogUploadAuth(nm2)
	if got := b.logAuth.loadToken(wantID); got != tok2 {
		t.Errorf("after refresh push, token = %q; want %q", got, tok2)
	}

	// Logout / nil netmap: clear SetAuthID but keep cached tokens for buffered logs.
	b.updateLogUploadAuth(nil)
	if got := b.logAuth.loadToken(wantID); got != tok2 {
		t.Errorf("after logout, cached token = %q; want retained %q", got, tok2)
	}
}

func TestFormatAuthID(t *testing.T) {
	const want = "nodeid:456"
	got := formatAuthID(456)
	if got != want {
		t.Errorf("formatAuthID = %q; want %q", got, want)
	}
}
