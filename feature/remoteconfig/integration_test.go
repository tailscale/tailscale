// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package remoteconfig_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
)

// TestRemoteConfigIntegration verifies that the /remoteapi/localapi/*
// c2n proxy handler is gated on Prefs.RemoteConfig and, when enabled,
// exposes the LocalAPI to the control plane with full permission.
func TestRemoteConfigIntegration(t *testing.T) {
	tstest.Parallel(t)
	env := integration.NewTestEnv(t)

	n := integration.NewTestNode(t, env)
	d := n.StartDaemon()
	defer d.MustCleanShutdown(t)

	n.AwaitListening()
	n.MustUp()
	n.AwaitRunning()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	nodeKey := n.MustStatus().Self.PublicKey
	if err := tstest.WaitFor(5*time.Second, func() error {
		return env.Control.AwaitNodeInMapRequest(ctx, nodeKey)
	}); err != nil {
		t.Fatal(err)
	}

	rt := env.Control.NodeRoundTripper(nodeKey)

	// doReq issues a c2n request and retries on error. The testcontrol
	// serveMap loop can race with the initial MapResponse delivery and
	// silently drop the first PingRequest, so we retry with a shorter
	// per-attempt deadline rather than relying on a single 30s call.
	doReq := func(method, path string, body []byte) *http.Response {
		t.Helper()
		var lastErr error
		for try := range 5 {
			reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
			var r io.Reader
			if body != nil {
				r = bytes.NewReader(body)
			}
			req, err := http.NewRequestWithContext(reqCtx, method, path, r)
			if err != nil {
				reqCancel()
				t.Fatalf("NewRequest(%s %s): %v", method, path, err)
			}
			resp, err := rt.RoundTrip(req)
			reqCancel()
			if err == nil {
				return resp
			}
			lastErr = err
			t.Logf("RoundTrip(%s %s) try %d: %v", method, path, try+1, err)
		}
		t.Fatalf("RoundTrip(%s %s) failed after retries: %v", method, path, lastErr)
		return nil
	}

	readBody := func(r *http.Response) string {
		t.Helper()
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(b)
	}

	// Case 1: RemoteConfig is off by default. The proxy must reject with 403.
	resp := doReq("GET", "/remoteapi/localapi/v0/prefs", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("with RemoteConfig=false, GET /remoteapi/localapi/v0/prefs: got %d %q; want 403", resp.StatusCode, readBody(resp))
	}
	resp.Body.Close()

	// Enable RemoteConfig locally.
	c := n.LocalClient()
	if _, err := c.EditPrefs(ctx, &ipn.MaskedPrefs{
		RemoteConfigSet: true,
		Prefs:           ipn.Prefs{RemoteConfig: true},
	}); err != nil {
		t.Fatalf("EditPrefs(RemoteConfig=true): %v", err)
	}

	// Case 2: With RemoteConfig on, the proxy should serve LocalAPI. GET prefs
	// must return the current prefs including RemoteConfig=true.
	resp = doReq("GET", "/remoteapi/localapi/v0/prefs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with RemoteConfig=true, GET /remoteapi/localapi/v0/prefs: got %d %q; want 200", resp.StatusCode, readBody(resp))
	}
	var gotPrefs ipn.Prefs
	if err := json.NewDecoder(resp.Body).Decode(&gotPrefs); err != nil {
		t.Fatalf("decode prefs from c2n proxy: %v", err)
	}
	resp.Body.Close()
	if !gotPrefs.RemoteConfig {
		t.Errorf("c2n GET prefs: RemoteConfig=false; want true")
	}

	// Case 3: PATCH prefs through the proxy toggling Hostname.
	const wantHostname = "remoteconfig-integration-test"
	patch, err := json.Marshal(&ipn.MaskedPrefs{
		HostnameSet: true,
		Prefs:       ipn.Prefs{Hostname: wantHostname},
	})
	if err != nil {
		t.Fatalf("marshal patch: %v", err)
	}
	resp = doReq("PATCH", "/remoteapi/localapi/v0/prefs", patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /remoteapi/localapi/v0/prefs: got %d %q; want 200", resp.StatusCode, readBody(resp))
	}
	resp.Body.Close()

	if err := tstest.WaitFor(5*time.Second, func() error {
		cur, err := c.GetPrefs(ctx)
		if err != nil {
			return err
		}
		if cur.Hostname != wantHostname {
			return fmt.Errorf("Hostname = %q; want %q", cur.Hostname, wantHostname)
		}
		return nil
	}); err != nil {
		t.Fatalf("PATCH did not land: %v", err)
	}

	// Case 4: Turn RemoteConfig off via the c2n proxy itself. Subsequent c2n
	// calls must be rejected as soon as the pref flips.
	patch, err = json.Marshal(&ipn.MaskedPrefs{
		RemoteConfigSet: true,
		Prefs:           ipn.Prefs{RemoteConfig: false},
	})
	if err != nil {
		t.Fatalf("marshal patch off: %v", err)
	}
	resp = doReq("PATCH", "/remoteapi/localapi/v0/prefs", patch)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH RemoteConfig=false via proxy: got %d %q; want 200", resp.StatusCode, readBody(resp))
	}
	resp.Body.Close()

	if err := tstest.WaitFor(5*time.Second, func() error {
		resp := doReq("GET", "/remoteapi/localapi/v0/prefs", nil)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return nil
		}
		return fmt.Errorf("still not 403; got %d", resp.StatusCode)
	}); err != nil {
		t.Fatalf("after disabling RemoteConfig, proxy did not start rejecting: %v", err)
	}

	// Case 5: A path outside the /remoteapi/localapi/ prefix should fall
	// through the router. The router returns "unknown c2n path" with 400.
	resp = doReq("GET", "/remoteapi/nope", nil)
	if resp.StatusCode == http.StatusOK {
		body := readBody(resp)
		t.Errorf("unexpected 200 for /remoteapi/nope; body=%q", body)
	}
	resp.Body.Close()
}
