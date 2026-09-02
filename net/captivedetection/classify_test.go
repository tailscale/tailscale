// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/util/must"
)

// tsEndpoint returns an Endpoint describing a Tailscale-operated /generate_204
// handler at the given base URL.
func tsEndpoint(base string) Endpoint {
	return Endpoint{
		URL:                        must.Get(url.Parse(base + "/generate_204")),
		StatusCode:                 http.StatusNoContent,
		SupportsTailscaleChallenge: true,
		Tier:                       TierHostname,
	}
}

// TestClassify covers the responses real captive portals send, and — just as
// importantly — the responses that only look like one. A false positive here
// tells a user on a merely-broken network to go find a login page that doesn't
// exist, so every "not a portal" case below is a guard worth keeping.
func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		// handler serves the probe. Handlers that want to produce a valid
		// challenge response must echo X-Tailscale-Challenge themselves.
		handler http.HandlerFunc
		// endpoint, if non-nil, is called with the server's base URL to build
		// the Endpoint. Defaults to tsEndpoint.
		endpoint func(base string) Endpoint
		wantSig  Signal
		wantURL  string
	}{
		// --- Real portal behaviors, all of which must be detected. ---
		{
			// Cisco Meraki, Aruba ClearPass, UniFi and most enterprise
			// gateways: redirect port 80 to an HTTPS login page.
			name: "redirect_to_login_page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://portal.example.net/login?mac=00:11:22:33:44:55", http.StatusFound)
			},
			wantSig: SignalRedirect,
			wantURL: "https://portal.example.net/login?mac=00:11:22:33:44:55",
		},
		{
			// Cisco ISE and FortiGate answer 200 with a meta-refresh instead
			// of a redirect, because some clients don't follow redirects.
			name: "meta_refresh_page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0; url=https://guest.example.net/portal/"></head></html>`))
			},
			wantSig: SignalHTML,
			wantURL: "https://guest.example.net/portal/",
		},
		{
			// Nomadix and similar hotel gateways bounce the browser with
			// JavaScript.
			name: "script_redirect_page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<html><body><script>window.location = "http://1.1.1.1/login.html";</script></body></html>`))
			},
			wantSig: SignalHTML,
			wantURL: "http://1.1.1.1/login.html",
		},
		{
			// A cheap gateway that serves its login form directly rather than
			// redirecting. There's no URL to hand the user, but the form itself
			// says what this is.
			name: "login_form_served_directly",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<!DOCTYPE html><html><body><h1>Please sign in</h1>` +
					`<form method="post" action="/auth"><input type="text" name="user">` +
					`<input type="password" name="pass"><input type="submit"></form></body></html>`))
			},
			wantSig: SignalHTML,
		},
		{
			// A bare <script> redirect with no surrounding HTML tags and a
			// content type that lies about it.
			name: "script_only_body_mislabeled",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<script>top.location.href="https://login.gogoinflight.example/";</script>`))
			},
			wantSig: SignalHTML,
			wantURL: "https://login.gogoinflight.example/",
		},
		{
			// RFC 6585's status code for exactly this situation.
			name: "http_511",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://gateway.example/portal")
				w.WriteHeader(http.StatusNetworkAuthenticationRequired)
			},
			wantSig: SignalHTTP511,
			wantURL: "http://gateway.example/portal",
		},
		{
			// Something answered with the right status code but couldn't have
			// known our challenge value, so it isn't the real server.
			name: "challenge_not_echoed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantSig: SignalChallengeTampered,
		},
		{
			name: "challenge_echoed_wrong",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Tailscale-Response", "response ts_somewhere.else")
				w.WriteHeader(http.StatusNoContent)
			},
			wantSig: SignalChallengeTampered,
		},

		// --- Responses that must NOT be reported as a portal. ---
		{
			// The happy path.
			name:    "clean_204",
			handler: echoChallenge(http.StatusNoContent, "", ""),
			wantSig: SignalClean,
		},
		{
			// A corporate HTTP proxy refusing an unapproved destination. Not a
			// captive portal: there is no login page to send the user to.
			name: "corporate_proxy_403",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Access denied by policy"))
			},
			wantSig: SignalUnexpectedStatus,
		},
		{
			// A transparent enterprise web proxy (Zscaler, Blue Coat, a
			// FortiGate web filter) answering a blocked destination with its
			// own HTML page. This is the same shape of evidence as a portal
			// page, and it is common in the corporate networks Tailscale runs
			// on, so getting it wrong would mean telling those users to go find
			// a login page that doesn't exist. What gives it away is that it
			// goes nowhere: no redirect, no onward URL, no form to fill in.
			name: "proxy_html_block_page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`<!DOCTYPE html><html><head><title>Access Denied</title></head>` +
					`<body><h1>Access Denied</h1><p>This site is blocked by your organization's ` +
					`security policy. Contact your administrator.</p></body></html>`))
			},
			wantSig: SignalUnexpectedStatus,
		},
		{
			// A load balancer or CDN having a bad day.
			name: "cdn_502",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			},
			wantSig: SignalUnexpectedStatus,
		},
		{
			// An unhealthy DERP node.
			name: "server_500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal error"))
			},
			wantSig: SignalUnexpectedStatus,
		},
		{
			// A redirect back to the same host is ordinary server behavior,
			// not interception.
			name: "same_host_redirect",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/generate_204/")
				w.WriteHeader(http.StatusMovedPermanently)
			},
			wantSig: SignalUnexpectedStatus,
		},
		{
			// A caching proxy that passes traffic through untouched. Worth
			// noting, not worth warning about on its own.
			name:    "transparent_proxy_headers",
			handler: echoChallenge(http.StatusNoContent, "Proxy-Connection", "keep-alive"),
			// The challenge still verified, so this endpoint is provably clean;
			// proxy headers only matter where we can't authenticate the server.
			wantSig: SignalClean,
		},

		// --- Third-party endpoints, which can indicate a portal but never clear one. ---
		{
			name: "third_party_success_is_no_evidence",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"))
			},
			endpoint: appleEndpoint,
			wantSig:  SignalNoEvidence,
		},
		{
			name: "third_party_intercepted",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://wifi.airline.example/onboard", http.StatusFound)
			},
			endpoint: appleEndpoint,
			wantSig:  SignalRedirect,
			wantURL:  "https://wifi.airline.example/onboard",
		},
		{
			// The portal answered 200, as Apple's server would, but with its
			// own page instead of the expected "Success" body. Inflight Wi-Fi
			// portals commonly do this.
			name: "third_party_wrong_content",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0;url=https://wifi.airline.example/buy"></head>` +
					`<body>Purchase Wi-Fi to continue</body></html>`))
			},
			endpoint: appleEndpoint,
			wantSig:  SignalHTML,
			wantURL:  "https://wifi.airline.example/buy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			mk := tt.endpoint
			if mk == nil {
				mk = tsEndpoint
			}
			e := mk(srv.URL)

			d := NewDetector(t.Logf)
			gotSig, gotURL, err := d.probeEndpoint(t.Context(), e, 0)
			if err != nil {
				t.Fatalf("probeEndpoint: %v", err)
			}
			if gotSig != tt.wantSig {
				t.Errorf("signal = %v, want %v", gotSig, tt.wantSig)
			}
			if gotURL != tt.wantURL {
				t.Errorf("portal URL = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

// TestClassifyBodyInNoContentResponse covers a portal that answers 204 but
// smuggles its login page into the body, hoping a detector only looks at the
// status code. Even a valid-looking challenge echo doesn't save it: a real 204
// handler has no body to send.
//
// This is exercised against a hand-built response rather than an httptest
// server because net/http refuses to write a body on a 204, so a Go server
// can't produce the case at all.
func TestClassifyBodyInNoContentResponse(t *testing.T) {
	e := tsEndpoint("http://derp1.example")
	r := &http.Response{
		StatusCode: http.StatusNoContent,
		Header: http.Header{
			"Content-Type":         []string{"text/html"},
			"X-Tailscale-Response": []string{"response " + challengeFor(e)},
		},
		Body: io.NopCloser(strings.NewReader(`<html><head><meta http-equiv="refresh" content="0;url=https://portal.example/"></head></html>`)),
	}

	gotSig, gotURL := classify(e, r, t.Logf)
	if gotSig != SignalHTML {
		t.Errorf("signal = %v, want %v", gotSig, SignalHTML)
	}
	if want := "https://portal.example/"; gotURL != want {
		t.Errorf("portal URL = %q, want %q", gotURL, want)
	}
}

// echoChallenge returns a handler that behaves like a real Tailscale
// /generate_204 endpoint, optionally setting an extra header.
func echoChallenge(status int, extraHeader, extraValue string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Get("X-Tailscale-Challenge"); c != "" {
			w.Header().Set("X-Tailscale-Response", "response "+c)
		}
		if extraHeader != "" {
			w.Header().Set(extraHeader, extraValue)
		}
		w.WriteHeader(status)
	}
}

func appleEndpoint(base string) Endpoint {
	return Endpoint{
		URL:             must.Get(url.Parse(base + "/hotspot-detect.html")),
		StatusCode:      http.StatusOK,
		ExpectedContent: "Success",
		Provider:        ThirdParty,
		Tier:            TierThirdParty,
	}
}

// TestVerdict checks how signals combine. The precedence rules are what keep a
// single ambiguous response from raising a warning on its own.
func TestVerdict(t *testing.T) {
	tests := []struct {
		name        string
		signals     []Signal
		want        Verdict
		wantConflct bool
	}{
		{
			name:    "nothing_probed",
			want:    VerdictUnknown,
			signals: nil,
		},
		{
			// A network with no Internet at all looks exactly like a walled
			// garden that drops our probes. We must not guess.
			name:    "everything_blackholed",
			signals: []Signal{SignalNoResponse, SignalNoResponse, SignalNoResponse},
			want:    VerdictUnknown,
		},
		{
			name:    "clean",
			signals: []Signal{SignalNoResponse, SignalClean},
			want:    VerdictNoPortal,
		},
		{
			name:    "definitive_redirect",
			signals: []Signal{SignalNoResponse, SignalRedirect},
			want:    VerdictPortal,
		},
		{
			name:    "definitive_dns_hijack",
			signals: []Signal{SignalNoResponse, SignalDNSHijack},
			want:    VerdictPortal,
		},
		{
			name:    "platform_hint",
			signals: []Signal{SignalPlatformHint},
			want:    VerdictPortal,
		},
		{
			// One unexplained error response is not enough. This is the case
			// that used to produce a false positive for anyone behind a
			// corporate proxy or in front of a sick DERP node.
			name:    "single_weak_signal",
			signals: []Signal{SignalUnexpectedStatus, SignalNoResponse},
			want:    VerdictUnknown,
		},
		{
			// A corporate proxy answering every port-80 request with a plain
			// block page produces a pile of these. It is not a captive portal
			// and there is nowhere to send the user to log in, so no number of
			// weak signals may add up to a warning.
			name:    "many_weak_signals",
			signals: []Signal{SignalUnexpectedStatus, SignalUnexpectedStatus, SignalUnexpectedStatus, SignalProxyHeaders},
			want:    VerdictUnknown,
		},
		{
			// Split behavior: some destinations intercepted, but one Tailscale
			// server was provably reachable. Staying quiet is the safe call.
			name:        "clean_beats_definitive",
			signals:     []Signal{SignalRedirect, SignalClean},
			want:        VerdictNoPortal,
			wantConflct: true,
		},
		{
			name:    "third_party_success_alone",
			signals: []Signal{SignalNoResponse, SignalNoEvidence},
			want:    VerdictUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ev evidence
			for _, s := range tt.signals {
				ev.add(s, "")
			}
			if got := ev.result().Verdict; got != tt.want {
				t.Errorf("verdict = %v, want %v", got, tt.want)
			}
			if got := ev.hasConflict(); got != tt.wantConflct {
				t.Errorf("hasConflict = %v, want %v", got, tt.wantConflct)
			}
		})
	}
}

// TestVerdictCarriesPortalURL checks that the login URL survives into the
// result, since telling the user where to go is the whole point of detecting
// the portal.
func TestVerdictCarriesPortalURL(t *testing.T) {
	var ev evidence
	ev.add(SignalNoResponse, "")
	ev.add(SignalRedirect, "https://portal.example/login")
	ev.add(SignalHTML, "https://other.example/")

	res := ev.result()
	if res.Verdict != VerdictPortal {
		t.Fatalf("verdict = %v, want %v", res.Verdict, VerdictPortal)
	}
	if want := "https://portal.example/login"; res.PortalURL != want {
		t.Errorf("PortalURL = %q, want %q (the first one learned)", res.PortalURL, want)
	}
}

func TestGotAnyResponse(t *testing.T) {
	tests := []struct {
		signals []Signal
		want    bool
	}{
		{nil, false},
		{[]Signal{SignalNoResponse}, false},
		{[]Signal{SignalNoResponse, SignalNoResponse}, false},
		{[]Signal{SignalNoResponse, SignalNoEvidence}, true},
		{[]Signal{SignalUnexpectedStatus}, true},
		{[]Signal{SignalClean}, true},
	}
	for _, tt := range tests {
		var ev evidence
		for _, s := range tt.signals {
			ev.add(s, "")
		}
		if got := ev.gotAnyResponse(); got != tt.want {
			t.Errorf("gotAnyResponse(%v) = %v, want %v", tt.signals, got, tt.want)
		}
	}
}

func TestSameHost(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com:80", "example.com", true},
		{"EXAMPLE.com", "example.com", true},
		{"example.com.", "example.com", true},
		{"example.com", "portal.example.com", false},
		{"1.2.3.4", "1.2.3.4:80", true},
		{"1.2.3.4", "5.6.7.8", false},
		{"[::1]:80", "[::1]", true},
	}
	for _, tt := range tests {
		if got := sameHost(tt.a, tt.b); got != tt.want {
			t.Errorf("sameHost(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestLooksLikeWebPage(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantOK      bool
		wantURL     string
	}{
		{
			name:        "html_content_type",
			contentType: "text/html",
			body:        "anything",
			wantOK:      true,
		},
		{
			name:   "html_sniffed_from_body",
			body:   "<html><body>hi</body></html>",
			wantOK: true,
		},
		{
			name:        "plain_text_is_not_a_page",
			contentType: "text/plain",
			body:        "Access denied by policy",
			wantOK:      false,
		},
		{
			name:   "empty_body_is_not_a_page",
			wantOK: false,
		},
		{
			name:        "relative_meta_refresh_url_dropped",
			contentType: "text/html",
			// A relative URL would resolve against our probe endpoint, not the
			// portal, so it's useless to show the user.
			body:    `<html><head><meta http-equiv="refresh" content="0;url=/login"></head></html>`,
			wantOK:  true,
			wantURL: "",
		},
		{
			name:        "absolute_meta_refresh_url_kept",
			contentType: "text/html",
			body:        `<html><head><meta http-equiv=refresh content="1; URL=https://p.example/x"></head></html>`,
			wantOK:      true,
			wantURL:     "https://p.example/x",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Response{Header: http.Header{}}
			if tt.contentType != "" {
				r.Header.Set("Content-Type", tt.contentType)
			}
			gotURL, gotOK := looksLikeWebPage(r, []byte(tt.body))
			if gotOK != tt.wantOK {
				t.Errorf("isPage = %v, want %v", gotOK, tt.wantOK)
			}
			if gotURL != tt.wantURL {
				t.Errorf("pageURL = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestHasLoginForm(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "password_field",
			body: `<form><input type="password" name="pw"></form>`,
			want: true,
		},
		{
			name: "password_field_unquoted",
			body: `<form><input name=pw type=password></form>`,
			want: true,
		},
		{
			name: "password_field_spaced",
			body: `<INPUT TYPE = "PASSWORD" NAME="pw">`,
			want: true,
		},
		{
			// A block page has no credentials to collect.
			name: "block_page",
			body: `<html><body><h1>Access Denied</h1><p>Blocked by policy.</p></body></html>`,
			want: false,
		},
		{
			// A search box is not a login form.
			name: "text_input_only",
			body: `<form><input type="text" name="q"></form>`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasLoginForm([]byte(tt.body)); got != tt.want {
				t.Errorf("hasLoginForm = %v, want %v", got, tt.want)
			}
		})
	}
}
