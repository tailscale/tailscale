// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package tshttpproxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSynologyProxyFromConfigCached(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.org/", nil)
	if err != nil {
		t.Fatal(err)
	}

	var orig string
	orig, synologyProxyConfigPath = synologyProxyConfigPath, filepath.Join(t.TempDir(), "proxy.conf")
	defer func() { synologyProxyConfigPath = orig }()

	t.Run("no config file", func(t *testing.T) {
		if _, err := os.Stat(synologyProxyConfigPath); err == nil {
			t.Fatalf("%s must not exist for this test", synologyProxyConfigPath)
		}

		cache.updated = time.Time{}
		cache.httpProxy = nil
		cache.httpsProxy = nil

		if val, err := synologyProxyFromConfigCached(req); val != nil || err != nil {
			t.Fatalf("got %s, %v; want nil, nil", val, err)
		}

		if got, want := cache.updated, time.Unix(0, 0); got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
		if cache.httpProxy != nil {
			t.Fatalf("got %s, want nil", cache.httpProxy)
		}
		if cache.httpsProxy != nil {
			t.Fatalf("got %s, want nil", cache.httpsProxy)
		}
	})

	t.Run("config file updated", func(t *testing.T) {
		cache.updated = time.Now()
		cache.httpProxy = nil
		cache.httpsProxy = nil

		if err := os.WriteFile(synologyProxyConfigPath, []byte(`
proxy_enabled=yes
http_host=10.0.0.55
http_port=80
https_host=10.0.0.66
https_port=443
		`), 0600); err != nil {
			t.Fatal(err)
		}

		val, err := synologyProxyFromConfigCached(req)
		if err != nil {
			t.Fatal(err)
		}

		if cache.httpProxy == nil {
			t.Fatal("http proxy was not cached")
		}
		if cache.httpsProxy == nil {
			t.Fatal("https proxy was not cached")
		}

		if want := urlMustParse("http://10.0.0.55:80"); val.String() != want.String() {
			t.Fatalf("got %s; want %s", val, want)
		}
	})

	t.Run("config file removed", func(t *testing.T) {
		cache.updated = time.Now()
		cache.httpProxy = urlMustParse("http://127.0.0.1/")
		cache.httpsProxy = urlMustParse("http://127.0.0.1/")

		if err := os.Remove(synologyProxyConfigPath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}

		val, err := synologyProxyFromConfigCached(req)
		if err != nil {
			t.Fatal(err)
		}
		if val != nil {
			t.Fatalf("got %s; want nil", val)
		}
		if cache.httpProxy != nil {
			t.Fatalf("got %s, want nil", cache.httpProxy)
		}
		if cache.httpsProxy != nil {
			t.Fatalf("got %s, want nil", cache.httpsProxy)
		}
	})

	t.Run("picks proxy from request scheme", func(t *testing.T) {
		cache.updated = time.Now()
		cache.httpProxy = nil
		cache.httpsProxy = nil

		if err := os.WriteFile(synologyProxyConfigPath, []byte(`
proxy_enabled=yes
http_host=10.0.0.55
http_port=80
https_host=10.0.0.66
https_port=443
		`), 0600); err != nil {
			t.Fatal(err)
		}

		httpReq, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		val, err := synologyProxyFromConfigCached(httpReq)
		if err != nil {
			t.Fatal(err)
		}
		if val == nil {
			t.Fatalf("got nil, want an http URL")
		}
		if got, want := val.String(), "http://10.0.0.55:80"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}

		httpsReq, err := http.NewRequest("GET", "https://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		val, err = synologyProxyFromConfigCached(httpsReq)
		if err != nil {
			t.Fatal(err)
		}
		if val == nil {
			t.Fatalf("got nil, want an http URL")
		}
		if got, want := val.String(), "http://10.0.0.66:443"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

func TestSynologyProxiesFromConfig(t *testing.T) {
	var (
		openReader io.ReadCloser
		openErr    error
	)
	var origOpen func() (io.ReadCloser, error)
	origOpen, openSynologyProxyConf = openSynologyProxyConf, func() (io.ReadCloser, error) {
		return openReader, openErr
	}
	defer func() { openSynologyProxyConf = origOpen }()

	t.Run("with config", func(t *testing.T) {
		mc := &mustCloser{Reader: strings.NewReader(`
proxy_user=foo
proxy_pwd=bar
proxy_enabled=yes
adv_enabled=yes
bypass_enabled=yes
auth_enabled=yes
https_host=10.0.0.66
https_port=8443
http_host=10.0.0.55
http_port=80
	`)}
		defer mc.check(t)
		openReader = mc

		httpProxy, httpsProxy, err := synologyProxiesFromConfig()

		if got, want := err, openErr; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}

		if got, want := httpsProxy, urlMustParse("http://foo:bar@10.0.0.66:8443"); got.String() != want.String() {
			t.Fatalf("got %s, want %s", got, want)
		}

		if got, want := err, openErr; got != want {
			t.Fatalf("got %s, want %s", got, want)
		}

		if got, want := httpProxy, urlMustParse("http://foo:bar@10.0.0.55:80"); got.String() != want.String() {
			t.Fatalf("got %s, want %s", got, want)
		}

	})

	t.Run("nonexistent config", func(t *testing.T) {
		openReader = nil
		openErr = os.ErrNotExist

		httpProxy, httpsProxy, err := synologyProxiesFromConfig()
		if err != nil {
			t.Fatalf("expected no error, got %s", err)
		}
		if httpProxy != nil {
			t.Fatalf("expected no url, got %s", httpProxy)
		}
		if httpsProxy != nil {
			t.Fatalf("expected no url, got %s", httpsProxy)
		}
	})

	t.Run("error opening config", func(t *testing.T) {
		openReader = nil
		openErr = errors.New("example error")

		httpProxy, httpsProxy, err := synologyProxiesFromConfig()
		if err != openErr {
			t.Fatalf("expected %s, got %s", openErr, err)
		}
		if httpProxy != nil {
			t.Fatalf("expected no url, got %s", httpProxy)
		}
		if httpsProxy != nil {
			t.Fatalf("expected no url, got %s", httpsProxy)
		}
	})

}

func TestParseSynologyConfig(t *testing.T) {
	cases := map[string]struct {
		input      string
		httpProxy  *url.URL
		httpsProxy *url.URL
		err        error
	}{
		"populated": {
			input: `
proxy_user=foo
proxy_pwd=bar
proxy_enabled=yes
adv_enabled=yes
bypass_enabled=yes
auth_enabled=yes
https_host=10.0.0.66
https_port=8443
http_host=10.0.0.55
http_port=80
`,
			httpProxy:  urlMustParse("http://foo:bar@10.0.0.55:80"),
			httpsProxy: urlMustParse("http://foo:bar@10.0.0.66:8443"),
			err:        nil,
		},
		"no-auth": {
			input: `
proxy_user=foo
proxy_pwd=bar
proxy_enabled=yes
adv_enabled=yes
bypass_enabled=yes
auth_enabled=no
https_host=10.0.0.66
https_port=8443
http_host=10.0.0.55
http_port=80
`,
			httpProxy:  urlMustParse("http://10.0.0.55:80"),
			httpsProxy: urlMustParse("http://10.0.0.66:8443"),
			err:        nil,
		},
		"http-only": {
			input: `
proxy_user=foo
proxy_pwd=bar
proxy_enabled=yes
adv_enabled=yes
bypass_enabled=yes
auth_enabled=yes
https_host=
https_port=8443
http_host=10.0.0.55
http_port=80
`,
			httpProxy:  urlMustParse("http://foo:bar@10.0.0.55:80"),
			httpsProxy: nil,
			err:        nil,
		},
		"empty": {
			input: `
proxy_user=
proxy_pwd=
proxy_enabled=
adv_enabled=
bypass_enabled=
auth_enabled=
https_host=
https_port=
http_host=
http_port=
`,
			httpProxy:  nil,
			httpsProxy: nil,
			err:        nil,
		},
	}

	for name, example := range cases {
		t.Run(name, func(t *testing.T) {
			httpProxy, httpsProxy, err := parseSynologyConfig(strings.NewReader(example.input))
			if err != example.err {
				t.Fatal(err)
			}
			if example.err != nil {
				return
			}

			if example.httpProxy == nil && httpProxy != nil {
				t.Fatalf("got %s, want nil", httpProxy)
			}

			if example.httpProxy != nil {
				if httpProxy == nil {
					t.Fatalf("got nil, want %s", example.httpProxy)
				}

				if got, want := example.httpProxy.String(), httpProxy.String(); got != want {
					t.Fatalf("got %s, want %s", got, want)
				}
			}

			if example.httpsProxy == nil && httpsProxy != nil {
				t.Fatalf("got %s, want nil", httpProxy)
			}

			if example.httpsProxy != nil {
				if httpsProxy == nil {
					t.Fatalf("got nil, want %s", example.httpsProxy)
				}

				if got, want := example.httpsProxy.String(), httpsProxy.String(); got != want {
					t.Fatalf("got %s, want %s", got, want)
				}
			}
		})
	}
}
func urlMustParse(u string) *url.URL {
	r, err := url.Parse(u)
	if err != nil {
		panic(fmt.Sprintf("urlMustParse: %s", err))
	}
	return r
}

type mustCloser struct {
	io.Reader
	closed bool
}

func (m *mustCloser) Close() error {
	m.closed = true
	return nil
}

func (m *mustCloser) check(t *testing.T) {
	if !m.closed {
		t.Errorf("mustCloser wrapping %#v was not closed at time of check", m.Reader)
	}
}
