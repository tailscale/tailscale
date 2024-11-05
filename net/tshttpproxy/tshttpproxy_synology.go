// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tshttpproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/util/lineiter"
)

// These vars are overridden for tests.
var (
	synologyProxyConfigPath = "/etc/proxy.conf"

	openSynologyProxyConf = func() (io.ReadCloser, error) {
		return os.Open(synologyProxyConfigPath)
	}
)

var cache struct {
	sync.Mutex
	httpProxy  *url.URL
	httpsProxy *url.URL
	updated    time.Time
}

func synologyProxyFromConfigCached(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, nil
	}

	cache.Lock()
	defer cache.Unlock()

	var err error
	modtime := mtime(synologyProxyConfigPath)

	if modtime != cache.updated {
		cache.httpProxy, cache.httpsProxy, err = synologyProxiesFromConfig()
		cache.updated = modtime
	}

	if req.URL.Scheme == "https" {
		return cache.httpsProxy, err
	}
	return cache.httpProxy, err
}

func synologyProxiesFromConfig() (*url.URL, *url.URL, error) {
	r, err := openSynologyProxyConf()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer r.Close()

	return parseSynologyConfig(r)
}

// parseSynologyConfig parses the Synology proxy configuration, and returns any
// http proxy, and any https proxy respectively, or an error if parsing fails.
func parseSynologyConfig(r io.Reader) (*url.URL, *url.URL, error) {
	cfg := map[string]string{}

	for lr := range lineiter.Reader(r) {
		line, err := lr.Value()
		if err != nil {
			return nil, nil, err
		}
		// accept and skip over empty lines
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			return nil, nil, fmt.Errorf("missing \"=\" in proxy.conf line: %q", line)
		}
		cfg[string(key)] = string(value)
	}

	if cfg["proxy_enabled"] != "yes" {
		return nil, nil, nil
	}

	httpProxyURL := new(url.URL)
	httpsProxyURL := new(url.URL)
	if cfg["auth_enabled"] == "yes" {
		httpProxyURL.User = url.UserPassword(cfg["proxy_user"], cfg["proxy_pwd"])
		httpsProxyURL.User = url.UserPassword(cfg["proxy_user"], cfg["proxy_pwd"])
	}

	// As far as we are aware, synology does not support tls proxies.
	httpProxyURL.Scheme = "http"
	httpsProxyURL.Scheme = "http"

	httpsProxyURL = addHostPort(httpsProxyURL, cfg["https_host"], cfg["https_port"])
	httpProxyURL = addHostPort(httpProxyURL, cfg["http_host"], cfg["http_port"])

	return httpProxyURL, httpsProxyURL, nil
}

// addHostPort adds to u the given host and port and returns the updated url, or
// if host is empty, it returns nil.
func addHostPort(u *url.URL, host, port string) *url.URL {
	if host == "" {
		return nil
	}

	if port == "" {
		u.Host = host
	} else {
		u.Host = net.JoinHostPort(host, port)
	}
	return u
}

// mtime stat's path and returns its modification time. If path does not exist,
// it returns the unix epoch.
func mtime(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Unix(0, 0)
	}
	return fi.ModTime()
}
