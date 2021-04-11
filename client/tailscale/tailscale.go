// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tailscale contains Tailscale client code.
package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
)

// TailscaledSocket is the tailscaled Unix socket.
var TailscaledSocket = paths.DefaultTailscaledSocket()

// tsClient does HTTP requests to the local Tailscale daemon.
var tsClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "local-tailscaled.sock:80" {
				return nil, fmt.Errorf("unexpected URL address %q", addr)
			}
			if TailscaledSocket == paths.DefaultTailscaledSocket() {
				// On macOS, when dialing from non-sandboxed program to sandboxed GUI running
				// a TCP server on a random port, find the random port. For HTTP connections,
				// we don't send the token. It gets added in an HTTP Basic-Auth header.
				if port, _, err := safesocket.LocalTCPPortAndToken(); err == nil {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", "localhost:"+strconv.Itoa(port))
				}
			}
			return safesocket.Connect(TailscaledSocket, 41112)
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

func send(ctx context.Context, method, path string, wantStatus int, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://local-tailscaled.sock"+path, body)
	if err != nil {
		return nil, err
	}
	res, err := DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != wantStatus {
		return nil, fmt.Errorf("HTTP %s: %s (expected %v)", res.Status, slurp, wantStatus)
	}
	return slurp, nil
}

func get200(ctx context.Context, path string) ([]byte, error) {
	return send(ctx, "GET", path, 200, nil)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
func WhoIs(ctx context.Context, remoteAddr string) (*tailcfg.WhoIsResponse, error) {
	body, err := get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr))
	if err != nil {
		return nil, err
	}
	r := new(tailcfg.WhoIsResponse)
	if err := json.Unmarshal(body, r); err != nil {
		if max := 200; len(body) > max {
			body = append(body[:max], "..."...)
		}
		return nil, fmt.Errorf("failed to parse JSON WhoIsResponse from %q", body)
	}
	return r, nil
}

// Goroutines returns a dump of the Tailscale daemon's current goroutines.
func Goroutines(ctx context.Context) ([]byte, error) {
	return get200(ctx, "/localapi/v0/goroutines")
}

// BugReport logs and returns a log marker that can be shared by the user with support.
func BugReport(ctx context.Context, note string) (string, error) {
	body, err := send(ctx, "POST", "/localapi/v0/bugreport?note="+url.QueryEscape(note), 200, nil)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
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
	body, err := get200(ctx, "/localapi/v0/status"+queryString)
	if err != nil {
		return nil, err
	}
	st := new(ipnstate.Status)
	if err := json.Unmarshal(body, st); err != nil {
		return nil, err
	}
	return st, nil
}

type WaitingFile struct {
	Name string
	Size int64
}

func WaitingFiles(ctx context.Context) ([]WaitingFile, error) {
	body, err := get200(ctx, "/localapi/v0/files/")
	if err != nil {
		return nil, err
	}
	var wfs []WaitingFile
	if err := json.Unmarshal(body, &wfs); err != nil {
		return nil, err
	}
	return wfs, nil
}

func DeleteWaitingFile(ctx context.Context, baseName string) error {
	_, err := send(ctx, "DELETE", "/localapi/v0/files/"+url.PathEscape(baseName), http.StatusNoContent, nil)
	return err
}

func GetWaitingFile(ctx context.Context, baseName string) (rc io.ReadCloser, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/files/"+url.PathEscape(baseName), nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := DoLocalRequest(req)
	if err != nil {
		return nil, 0, err
	}
	if res.ContentLength == -1 {
		res.Body.Close()
		return nil, 0, fmt.Errorf("unexpected chunking")
	}
	if res.StatusCode != 200 {
		body, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return nil, 0, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}
	return res.Body, res.ContentLength, nil
}

func CheckIPForwarding(ctx context.Context) error {
	body, err := get200(ctx, "/localapi/v0/check-ip-forwarding")
	if err != nil {
		return err
	}
	var jres struct {
		Warning string
	}
	if err := json.Unmarshal(body, &jres); err != nil {
		return fmt.Errorf("invalid JSON from check-ip-forwarding: %w", err)
	}
	if jres.Warning != "" {
		return errors.New(jres.Warning)
	}
	return nil
}

func GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
	body, err := get200(ctx, "/localapi/v0/prefs")
	if err != nil {
		return nil, err
	}
	var p ipn.Prefs
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid prefs JSON: %w", err)
	}
	return &p, nil
}

func EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	mpj, err := json.Marshal(mp)
	if err != nil {
		return nil, err
	}
	body, err := send(ctx, "POST", "/localapi/v0/prefs", http.StatusOK, bytes.NewReader(mpj))
	if err != nil {
		return nil, err
	}
	var p ipn.Prefs
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid prefs JSON: %w", err)
	}
	return &p, nil
}

func Logout(ctx context.Context) error {
	_, err := send(ctx, "POST", "/localapi/v0/logout", http.StatusNoContent, nil)
	return err
}
