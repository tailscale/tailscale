// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
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
			nodecap.LogUploadAuth: {tailcfg.RawMessage(`"` + tok + `"`)},
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
			nodecap.LogUploadAuth: {tailcfg.RawMessage(`"` + tok2 + `"`)},
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

func TestLogUploadAuthNotPublished(t *testing.T) {
	b := newTestLocalBackend(t)
	if buildfeatures.HasLogTail {
		lg := logtail.NewLogger(logtail.Config{
			BaseURL: "http://127.0.0.1:1", // never dialed
		}, t.Logf)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = lg.Shutdown(ctx)
		b.SetLogUploader(lg)
	}

	const tok = "super-secret-log-token"
	const other = "keep-me"
	node := &tailcfg.Node{
		ID:           7,
		User:         1,
		Addresses:    []netip.Prefix{netip.MustParsePrefix("100.64.0.7/32")},
		Capabilities: []nodecap.Cap{nodecap.LogUploadAuth, nodecap.Debug},
		CapMap: tailcfg.NodeCapMap{
			nodecap.LogUploadAuth: {tailcfg.RawMessage(`"` + tok + `"`)},
			nodecap.Debug:         {tailcfg.RawMessage(`"` + other + `"`)},
		},
	}
	caps := set.Of(nodecap.LogUploadAuth, nodecap.Debug)
	nm := &netmap.NetworkMap{
		SelfNode: node.View(),
		AllCaps:  caps,
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			1: (&tailcfg.UserProfile{ID: 1, LoginName: "ada@example.com"}).View(),
		},
	}

	b.mu.Lock()
	b.setNetMapLocked(nm)
	published := b.currentNode().NetMap()
	b.mu.Unlock()

	if published.SelfNode.CapMap().Contains(nodecap.LogUploadAuth) {
		t.Errorf("installed CapMap still contains %s", nodecap.LogUploadAuth)
	}
	if published.AllCaps.Contains(nodecap.LogUploadAuth) {
		t.Errorf("installed AllCaps still contains %s", nodecap.LogUploadAuth)
	}
	if !published.SelfNode.CapMap().Contains(nodecap.Debug) {
		t.Errorf("installed CapMap dropped %s", nodecap.Debug)
	}
	if slices.Contains(published.SelfNode.Capabilities().AsSlice(), nodecap.LogUploadAuth) {
		t.Errorf("installed Capabilities still contains %s", nodecap.LogUploadAuth)
	}
	if !slices.Contains(published.SelfNode.Capabilities().AsSlice(), nodecap.Debug) {
		t.Errorf("installed Capabilities dropped %s", nodecap.Debug)
	}
	if !published.AllCaps.Contains(nodecap.Debug) {
		t.Errorf("installed AllCaps dropped %s", nodecap.Debug)
	}
	// The control-client node and cap set must be left intact.
	if !node.CapMap.Contains(nodecap.LogUploadAuth) {
		t.Errorf("source node CapMap was mutated")
	}
	if !caps.Contains(nodecap.LogUploadAuth) {
		t.Errorf("source AllCaps was mutated")
	}
	if buildfeatures.HasLogTail {
		if got := b.logAuth.loadToken(formatAuthID(node.ID)); got != tok {
			t.Errorf("cached token = %q; want %q", got, tok)
		}
	}

	// Same netmap pointer the caller uses for SelfChange notifications.
	if nm.SelfNode.CapMap().Contains(nodecap.LogUploadAuth) {
		t.Errorf("SelfChange netmap still contains %s", nodecap.LogUploadAuth)
	}

	st := b.Status()
	if st.Self == nil {
		t.Fatal("status self node is nil")
	}
	if st.Self.CapMap.Contains(nodecap.LogUploadAuth) {
		t.Errorf("status CapMap contains %s", nodecap.LogUploadAuth)
	}
	if !st.Self.CapMap.Contains(nodecap.Debug) {
		t.Errorf("status CapMap dropped %s", nodecap.Debug)
	}

	who, _, ok := b.WhoIs("", netip.AddrPortFrom(netip.MustParseAddr("100.64.0.7"), 0))
	if !ok {
		t.Fatal("WhoIs(self) failed")
	}
	if who.CapMap().Contains(nodecap.LogUploadAuth) {
		t.Errorf("WhoIs CapMap contains %s", nodecap.LogUploadAuth)
	}

	// Status JSON, WhoIs, and the netmap used by the c2n debug dump.
	publishedJSON, err := json.Marshal(published)
	if err != nil {
		t.Fatalf("marshal published netmap: %v", err)
	}
	statusJSON, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	whoJSON, err := json.Marshal(who)
	if err != nil {
		t.Fatalf("marshal WhoIs node: %v", err)
	}
	dump := b.currentNode().netMapWithPeers()
	dumpJSON, err := json.Marshal(dump)
	if err != nil {
		t.Fatalf("marshal netMapWithPeers: %v", err)
	}
	for _, blob := range []struct {
		name string
		js   []byte
	}{
		{"published netmap", publishedJSON},
		{"status", statusJSON},
		{"WhoIs", whoJSON},
		{"c2n netmap", dumpJSON},
	} {
		if bytes.Contains(blob.js, []byte(tok)) {
			t.Errorf("%s JSON contains the log upload token", blob.name)
		}
	}
}
