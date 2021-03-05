// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tailscale contains Tailscale client code.
package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
)

// tsClient does HTTP requests to the local Tailscale daemon.
var tsClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "local-tailscaled.sock:80" {
				return nil, fmt.Errorf("unexpected URL address %q", addr)
			}
			// On macOS, when dialing from non-sandboxed program to sandboxed GUI running
			// a TCP server on a random port, find the random port. For HTTP connections,
			// we don't send the token. It gets added in an HTTP Basic-Auth header.
			if port, _, err := safesocket.LocalTCPPortAndToken(); err == nil {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", "localhost:"+strconv.Itoa(port))
			}
			return safesocket.ConnectDefault()
		},
	},
}

// DoLocalRequest makes an HTTP request to the local machine's Tailscale daemon.
//
// URLs are of the form http://local-tailscaled.sock/localapi/v0/whois?ip=1.2.3.4.
//
// The hostname must be "local-tailscaled.sock", even though it
// doesn't actually do any DNS lookup. The actual means of connecting to and
// authenticating to the local Tailscale daemon vary by platform.
//
// DoLocalRequest may mutate the request to add Authorization headers.
func DoLocalRequest(req *http.Request) (*http.Response, error) {
	if _, token, err := safesocket.LocalTCPPortAndToken(); err == nil {
		req.SetBasicAuth("", token)
	}
	return tsClient.Do(req)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
func WhoIs(ctx context.Context, remoteAddr string) (*tailcfg.WhoIsResponse, error) {
	var ip string
	if net.ParseIP(remoteAddr) != nil {
		ip = remoteAddr
	} else {
		var err error
		ip, _, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid remoteAddr %q", remoteAddr)
		}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/whois?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	res, err := DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	slurp, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, slurp)
	}
	r := new(tailcfg.WhoIsResponse)
	if err := json.Unmarshal(slurp, r); err != nil {
		if max := 200; len(slurp) > max {
			slurp = slurp[:max]
		}
		return nil, fmt.Errorf("failed to parse JSON WhoIsResponse from %q", slurp)
	}
	return r, nil
}
