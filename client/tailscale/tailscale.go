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

	"tailscale.com/ipn/ipnstate"
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
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr), nil)
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

// Goroutines returns a dump of the Tailscale daemon's current goroutines.
func Goroutines(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/goroutines", nil)
	if err != nil {
		return nil, err
	}
	res, err := DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}
	return body, nil
}

// Status returns the Tailscale daemon's status.
func Status(ctx context.Context) (*ipnstate.Status, error) {
	return status(ctx, "")
}

// StatusWithPeers returns the Tailscale daemon's status, without the peer info.
func StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return status(ctx, "?peers=false")
}

func status(ctx context.Context, queryString string) (*ipnstate.Status, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/status"+queryString, nil)
	if err != nil {
		return nil, err
	}
	res, err := DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := ioutil.ReadAll(res.Body)
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}
	st := new(ipnstate.Status)
	if err := json.NewDecoder(res.Body).Decode(st); err != nil {
		return nil, err
	}
	return st, nil
}
