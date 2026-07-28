// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
)

// TestWebClientLocalAccess verifies that, after enabling the web client on a
// single node, the node's own Tailscale IP responds on port 5252 and that a
// same-node session can be created and used to access the management UI as
// the owner.
func TestWebClientLocalAccess(t *testing.T) {
	env := vmtest.New(t)
	node := easy(env)
	env.Start()

	enableWebClient(t, env, node)
	assertOwnerSessionFlow(t, env, node, webClientBaseURL(t, env, node), viewerName(t, env, node))
}

// TestWebClientRemoteAccess verifies that a peer node on the same tailnet can
// create a session on a target's web client and then use it to access the
// management UI as the owner, and that after re-logging-in under a different
// user the target rejects new session attempts with 401 "not-owner".
//
// This exercises:
//   - netstack interception of incoming :5252 traffic, gated by
//     ShouldExposeRemoteWebClient (ipn/ipnlocal/netstack.go)
//   - cross-node WhoIs identifying the caller (client/web/web.go)
//   - cookie issuance + the same-user "owner" path through getSession +
//     authorizeRequest (client/web/auth.go)
//   - the not-owner rejection path (client/web/auth.go)
func TestWebClientRemoteAccess(t *testing.T) {
	env := vmtest.New(t, vmtest.SameTailnetUser(), vmtest.AllOnline())
	target := easy(env)
	client := easy(env)
	env.Start()

	enableWebClient(t, env, target)
	baseURL := webClientBaseURL(t, env, target)

	assertOwnerSessionFlow(t, env, client, baseURL, viewerName(t, env, client))

	// Re-log-in the client under a fresh identity that is no longer the
	// target's owner, and assert /api/auth/session/new is rejected.
	env.ControlServer().AllNodesSameUser = false
	env.Relogin(client)
	assertSessionRejectedNotOwner(t, env, client, baseURL)
}

// enableWebClient turns on the management web client on n via "tailscale set
// --webclient", fataling the test on error.
func enableWebClient(t *testing.T, env *vmtest.Env, n *vmtest.Node) {
	t.Helper()
	if out, err := env.Tailscale(n, "set", "--webclient"); err != nil {
		t.Fatalf("tailscale set --webclient on %s: %v\n%s", n.Name(), err, out)
	}
}

// webClientBaseURL returns the http://<tsip>:5252 base URL for n's management
// web client.
func webClientBaseURL(t *testing.T, env *vmtest.Env, n *vmtest.Node) string {
	t.Helper()
	st := env.Status(n)
	if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		t.Fatalf("%s has no Tailscale IPs; status=%+v", n.Name(), st)
	}
	return fmt.Sprintf("http://%s:5252", st.Self.TailscaleIPs[0])
}

// viewerName returns the DNS-name form (no trailing dot) that the web client
// uses in viewerIdentity.nodeName for a request from n.
func viewerName(t *testing.T, env *vmtest.Env, n *vmtest.Node) string {
	t.Helper()
	st := env.Status(n)
	if st.Self == nil {
		t.Fatalf("%s has no Self status", n.Name())
	}
	return strings.TrimSuffix(st.Self.DNSName, ".")
}

// assertOwnerSessionFlow exercises the canonical owner flow against the
// management web client at baseURL, calling from `from`:
//
//  1. GET /api/auth without a cookie: the server is reachable, identifies the
//     caller as expectViewer, and reports authorized=false (no session yet).
//  2. GET /api/auth/session/new: the web client posts to
//     /machine/webclient/init on the test control server via Noise; control
//     returns a placeholder auth URL; the response sets a TS-Web-Session
//     cookie with PendingAuth=true.
//  3. GET /api/auth with the cookie: awaitUserAuth posts to
//     /machine/webclient/wait on the test control server, which returns
//     Complete=true; the session is marked Authenticated and the response
//     reports authorized=true.
//
// This exercises the check-mode path in client/web/auth.go (the
// controlSupportsCheckMode branch), which fires for the natlab test control
// server's hostname (control.tailscale).
//
// Use this for both same-node (self-as-owner) and cross-node-same-user
// (peer-as-owner) paths: the assertions are identical.
func assertOwnerSessionFlow(t *testing.T, env *vmtest.Env, from *vmtest.Node, baseURL, expectViewer string) {
	t.Helper()

	res, err := env.HTTPGetStatus(from, baseURL+"/api/auth")
	if err != nil {
		t.Fatalf("GET /api/auth: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("GET /api/auth: status = %d, want 200; body=%s", res.Status, res.Body)
	}
	if !strings.Contains(res.Body, `"serverMode":"manage"`) {
		t.Errorf("/api/auth response missing serverMode=manage: %s", res.Body)
	}
	if expectViewer != "" && !strings.Contains(res.Body, fmt.Sprintf(`"nodeName":%q`, expectViewer)) {
		t.Errorf("/api/auth viewerIdentity does not name %q: %s", expectViewer, res.Body)
	}
	if strings.Contains(res.Body, `"authorized":true`) {
		t.Errorf("unauthenticated /api/auth should not report authorized=true: %s", res.Body)
	}

	res, err = env.HTTPGetStatus(from, baseURL+"/api/auth/session/new")
	if err != nil {
		t.Fatalf("GET /api/auth/session/new: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("GET /api/auth/session/new: status = %d, want 200; body=%s", res.Status, res.Body)
	}
	var cookie *http.Cookie
	for _, c := range res.SetCookies {
		if c.Name == "TS-Web-Session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("/api/auth/session/new did not set a TS-Web-Session cookie; got %v", res.SetCookies)
	}

	res, err = env.HTTPGetStatus(from, baseURL+"/api/auth", cookie)
	if err != nil {
		t.Fatalf("GET /api/auth (authed): %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("GET /api/auth (authed): status = %d, want 200; body=%s", res.Status, res.Body)
	}
	if !strings.Contains(res.Body, `"authorized":true`) {
		t.Errorf("authenticated /api/auth should report authorized=true: %s", res.Body)
	}
}

// assertSessionRejectedNotOwner asserts that /api/auth/session/new from `from`
// against baseURL returns 401 with body "not-owner" -- the rejection path in
// client/web/auth.go's getSession for a source node whose user is not the
// web client owner.
func assertSessionRejectedNotOwner(t *testing.T, env *vmtest.Env, from *vmtest.Node, baseURL string) {
	t.Helper()
	res, err := env.HTTPGetStatus(from, baseURL+"/api/auth/session/new")
	if err != nil {
		t.Fatalf("GET /api/auth/session/new from non-owner: %v", err)
	}
	if res.Status != 401 {
		t.Errorf("GET /api/auth/session/new from non-owner: status = %d, want 401; body=%s", res.Status, res.Body)
	}
	if !strings.Contains(res.Body, "not-owner") {
		t.Errorf("non-owner response body does not contain \"not-owner\": %s", res.Body)
	}
}
