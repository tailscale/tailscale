// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tshttpproxy

import (
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/util/must"
)

func TestGetAuthHeaderNoResult(t *testing.T) {
	const proxyURL = "http://127.0.0.1:38274"

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	got, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if runtime.GOOS == "windows" && strings.HasPrefix(got, "Negotiate") {
		t.Logf("didn't get empty result, but got acceptable Windows Negotiate header")
		return
	}
	if got != "" {
		t.Fatalf("GetAuthHeader(%q) = %q; want empty string", proxyURL, got)
	}
}

func TestGetAuthHeaderBasicAuth(t *testing.T) {
	const proxyURL = "http://user:password@127.0.0.1:38274"
	const want = "Basic dXNlcjpwYXNzd29yZA=="

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("can't parse %q: %v", proxyURL, err)
	}

	got, err := GetAuthHeader(u)
	if err != nil {
		t.Fatalf("can't get auth header value: %v", err)
	}

	if got != want {
		t.Fatalf("GetAuthHeader(%q) = %q; want %q", proxyURL, got, want)
	}
}

func TestProxyFromEnvironment_setNoProxyUntil(t *testing.T) {
	const fakeProxyEnv = "10.1.2.3:456"
	const fakeProxyFull = "http://" + fakeProxyEnv

	defer os.Setenv("HTTPS_PROXY", os.Getenv("HTTPS_PROXY"))
	os.Setenv("HTTPS_PROXY", fakeProxyEnv)

	req := &http.Request{URL: must.Get(url.Parse("https://example.com/"))}
	for i := range 3 {
		switch i {
		case 1:
			setNoProxyUntil(time.Minute)
		case 2:
			setNoProxyUntil(0)
		}
		got, err := ProxyFromEnvironment(req)
		if err != nil {
			t.Fatalf("[%d] ProxyFromEnvironment: %v", i, err)
		}
		if got == nil || got.String() != fakeProxyFull {
			t.Errorf("[%d] Got proxy %v; want %v", i, got, fakeProxyFull)
		}
	}

}

func TestSetSelfProxy(t *testing.T) {
	// Ensure we clean everything up at the end of our test
	t.Cleanup(func() {
		config = nil
		proxyFunc = nil
	})

	testCases := []struct {
		name      string
		env       map[string]string
		self      []string
		wantHTTP  string
		wantHTTPS string
	}{
		{
			name: "no self proxy",
			env: map[string]string{
				"HTTP_PROXY":  "127.0.0.1:1234",
				"HTTPS_PROXY": "127.0.0.1:1234",
			},
			self:      nil,
			wantHTTP:  "127.0.0.1:1234",
			wantHTTPS: "127.0.0.1:1234",
		},
		{
			name: "skip proxies",
			env: map[string]string{
				"HTTP_PROXY":  "127.0.0.1:1234",
				"HTTPS_PROXY": "127.0.0.1:5678",
			},
			self:      []string{"127.0.0.1:1234", "127.0.0.1:5678"},
			wantHTTP:  "", // skipped
			wantHTTPS: "", // skipped
		},
		{
			name: "localhost normalization of env var",
			env: map[string]string{
				"HTTP_PROXY":  "localhost:1234",
				"HTTPS_PROXY": "[::1]:5678",
			},
			self:      []string{"127.0.0.1:1234", "127.0.0.1:5678"},
			wantHTTP:  "", // skipped
			wantHTTPS: "", // skipped
		},
		{
			name: "localhost normalization of addr",
			env: map[string]string{
				"HTTP_PROXY":  "127.0.0.1:1234",
				"HTTPS_PROXY": "127.0.0.1:1234",
			},
			self:      []string{"[::1]:1234"},
			wantHTTP:  "", // skipped
			wantHTTPS: "", // skipped
		},
		{
			name: "no ports",
			env: map[string]string{
				"HTTP_PROXY":  "myproxy",
				"HTTPS_PROXY": "myproxy",
			},
			self:      []string{"127.0.0.1:1234"},
			wantHTTP:  "myproxy",
			wantHTTPS: "myproxy",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				oldEnv, found := os.LookupEnv(k)
				if found {
					t.Cleanup(func() {
						os.Setenv(k, oldEnv)
					})
				}
				os.Setenv(k, v)
			}

			// Reset computed variables
			config = nil
			proxyFunc = func(*url.URL) (*url.URL, error) {
				panic("should not be called")
			}

			SetSelfProxy(tt.self...)

			if got := config.HTTPProxy; got != tt.wantHTTP {
				t.Errorf("got HTTPProxy=%q; want %q", got, tt.wantHTTP)
			}
			if got := config.HTTPSProxy; got != tt.wantHTTPS {
				t.Errorf("got HTTPSProxy=%q; want %q", got, tt.wantHTTPS)
			}
			if proxyFunc != nil {
				t.Errorf("wanted nil proxyFunc")
			}

			// Verify that we do actually proxy through the
			// expected proxy, if we have one configured.
			pf := getProxyFunc()
			if tt.wantHTTP != "" {
				want := "http://" + tt.wantHTTP

				uu, _ := url.Parse("http://tailscale.com")
				dest, err := pf(uu)
				if err != nil {
					t.Error(err)
				} else if dest.String() != want {
					t.Errorf("got dest=%q; want %q", dest, want)
				}
			}
			if tt.wantHTTPS != "" {
				want := "http://" + tt.wantHTTPS

				uu, _ := url.Parse("https://tailscale.com")
				dest, err := pf(uu)
				if err != nil {
					t.Error(err)
				} else if dest.String() != want {
					t.Errorf("got dest=%q; want %q", dest, want)
				}
			}
		})
	}
}
