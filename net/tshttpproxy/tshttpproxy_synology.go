// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

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

	"tailscale.com/util/lineread"
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
	proxy   *url.URL
	updated time.Time
}

func synologyProxyFromConfigCached(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, nil
	}

	cache.Lock()
	defer cache.Unlock()

	modtime := mtime(synologyProxyConfigPath)

	if cache.updated == modtime {
		return cache.proxy, nil
	}

	val, err := synologyProxyFromConfig(req)
	cache.proxy = val

	cache.updated = modtime

	return val, err
}

func synologyProxyFromConfig(req *http.Request) (*url.URL, error) {
	r, err := openSynologyProxyConf()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer r.Close()

	return parseSynologyConfig(r)
}

func parseSynologyConfig(r io.Reader) (*url.URL, error) {
	cfg := map[string]string{}

	if err := lineread.Reader(r, func(line []byte) error {
		// accept and skip over empty lines
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			return nil
		}

		key, value, ok := strings.Cut(string(line), "=")
		if !ok {
			return fmt.Errorf("missing \"=\" in proxy.conf line: %q", line)
		}
		cfg[string(key)] = string(value)
		return nil
	}); err != nil {
		return nil, err
	}

	if cfg["proxy_enabled"] != "yes" {
		return nil, nil
	}

	proxyURL := &url.URL{
		Scheme: "http", // regardless of proxy type
	}
	if cfg["auth_enabled"] == "yes" {
		proxyURL.User = url.UserPassword(cfg["proxy_user"], cfg["proxy_pwd"])
	}

	host, port := cfg["https_host"], cfg["https_port"]
	if host == "" {
		host, port = cfg["http_host"], cfg["http_port"]
	}

	if host == "" {
		return nil, nil
	}

	if port != "" {
		proxyURL.Host = net.JoinHostPort(host, port)
	} else {
		proxyURL.Host = host
	}

	return proxyURL, nil
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
