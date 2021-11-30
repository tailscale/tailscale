// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tailscale contains Tailscale client code.
package tailscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/version"
)

var (
	// TailscaledSocket is the tailscaled Unix socket. It's used by the TailscaledDialer.
	TailscaledSocket = paths.DefaultTailscaledSocket()

	// TailscaledDialer is the DialContext func that connects to the local machine's
	// tailscaled or equivalent.
	TailscaledDialer = defaultDialer
)

func defaultDialer(ctx context.Context, network, addr string) (net.Conn, error) {
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
	return safesocket.Connect(TailscaledSocket, safesocket.WindowsLocalPort)
}

var (
	// tsClient does HTTP requests to the local Tailscale daemon.
	// We lazily initialize the client in case the caller wants to
	// override TailscaledDialer.
	tsClient     *http.Client
	tsClientOnce sync.Once
)

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
	tsClientOnce.Do(func() {
		tsClient = &http.Client{
			Transport: &http.Transport{
				DialContext: TailscaledDialer,
			},
		}
	})
	if _, token, err := safesocket.LocalTCPPortAndToken(); err == nil {
		req.SetBasicAuth("", token)
	}
	return tsClient.Do(req)
}

func doLocalRequestNiceError(req *http.Request) (*http.Response, error) {
	res, err := DoLocalRequest(req)
	if err == nil {
		if server := res.Header.Get("Tailscale-Version"); server != "" && server != version.Long && onVersionMismatch != nil {
			onVersionMismatch(version.Long, server)
		}
		return res, nil
	}
	if ue, ok := err.(*url.Error); ok {
		if oe, ok := ue.Err.(*net.OpError); ok && oe.Op == "dial" {
			path := req.URL.Path
			pathPrefix := path
			if i := strings.Index(path, "?"); i != -1 {
				pathPrefix = path[:i]
			}
			return nil, fmt.Errorf("Failed to connect to local Tailscale daemon for %s; %s Error: %w", pathPrefix, tailscaledConnectHint(), oe)
		}
	}
	return nil, err
}

type errorJSON struct {
	Error string
}

// AccessDeniedError is an error due to permissions.
type AccessDeniedError struct {
	err error
}

func (e *AccessDeniedError) Error() string { return fmt.Sprintf("Access denied: %v", e.err) }
func (e *AccessDeniedError) Unwrap() error { return e.err }

// IsAccessDeniedError reports whether err is or wraps an AccessDeniedError.
func IsAccessDeniedError(err error) bool {
	var ae *AccessDeniedError
	return errors.As(err, &ae)
}

// bestError returns either err, or if body contains a valid JSON
// object of type errorJSON, its non-empty error body.
func bestError(err error, body []byte) error {
	var j errorJSON
	if err := json.Unmarshal(body, &j); err == nil && j.Error != "" {
		return errors.New(j.Error)
	}
	return err
}

func errorMessageFromBody(body []byte) string {
	var j errorJSON
	if err := json.Unmarshal(body, &j); err == nil && j.Error != "" {
		return j.Error
	}
	return strings.TrimSpace(string(body))
}

var onVersionMismatch func(clientVer, serverVer string)

// SetVersionMismatchHandler sets f as the version mismatch handler
// to be called when the client (the current process) has a version
// number that doesn't match the server's declared version.
func SetVersionMismatchHandler(f func(clientVer, serverVer string)) {
	onVersionMismatch = f
}

func send(ctx context.Context, method, path string, wantStatus int, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://local-tailscaled.sock"+path, body)
	if err != nil {
		return nil, err
	}
	res, err := doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != wantStatus {
		if res.StatusCode == 403 {
			return nil, &AccessDeniedError{errors.New(errorMessageFromBody(slurp))}
		}
		err := fmt.Errorf("HTTP %s: %s (expected %v)", res.Status, slurp, wantStatus)
		return nil, bestError(err, slurp)
	}
	return slurp, nil
}

func get200(ctx context.Context, path string) ([]byte, error) {
	return send(ctx, "GET", path, 200, nil)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
func WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	body, err := get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr))
	if err != nil {
		return nil, err
	}
	r := new(apitype.WhoIsResponse)
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

// DaemonMetrics returns the Tailscale daemon's metrics in
// the Prometheus text exposition format.
func DaemonMetrics(ctx context.Context) ([]byte, error) {
	return get200(ctx, "/localapi/v0/metrics")
}

// Profile returns a pprof profile of the Tailscale daemon.
func Profile(ctx context.Context, pprofType string, sec int) ([]byte, error) {
	var secArg string
	if sec < 0 || sec > 300 {
		return nil, errors.New("duration out of range")
	}
	if sec != 0 || pprofType == "profile" {
		secArg = fmt.Sprint(sec)
	}
	return get200(ctx, fmt.Sprintf("/localapi/v0/profile?name=%s&seconds=%v", url.QueryEscape(pprofType), secArg))
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

func WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	body, err := get200(ctx, "/localapi/v0/files/")
	if err != nil {
		return nil, err
	}
	var wfs []apitype.WaitingFile
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

func FileTargets(ctx context.Context) ([]apitype.FileTarget, error) {
	body, err := get200(ctx, "/localapi/v0/file-targets")
	if err != nil {
		return nil, err
	}
	var fts []apitype.FileTarget
	if err := json.Unmarshal(body, &fts); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return fts, nil
}

// PushFile sends Taildrop file r to target.
//
// A size of -1 means unknown.
// The name parameter is the original filename, not escaped.
func PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://local-tailscaled.sock/localapi/v0/file-put/"+string(target)+"/"+url.PathEscape(name), r)
	if err != nil {
		return err
	}
	if size != -1 {
		req.ContentLength = size
	}
	res, err := doLocalRequestNiceError(req)
	if err != nil {
		return err
	}
	if res.StatusCode == 200 {
		io.Copy(io.Discard, res.Body)
		return nil
	}
	all, _ := io.ReadAll(res.Body)
	return fmt.Errorf("%s: %s", res.Status, all)
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
	body, err := send(ctx, "PATCH", "/localapi/v0/prefs", http.StatusOK, bytes.NewReader(mpj))
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

// SetDNS adds a DNS TXT record for the given domain name, containing
// the provided TXT value. The intended use case is answering
// LetsEncrypt/ACME dns-01 challenges.
//
// The control plane will only permit SetDNS requests with very
// specific names and values. The name should be
// "_acme-challenge." + your node's MagicDNS name. It's expected that
// clients cache the certs from LetsEncrypt (or whichever CA is
// providing them) and only request new ones as needed; the control plane
// rate limits SetDNS requests.
//
// This is a low-level interface; it's expected that most Tailscale
// users use a higher level interface to getting/using TLS
// certificates.
func SetDNS(ctx context.Context, name, value string) error {
	v := url.Values{}
	v.Set("name", name)
	v.Set("value", value)
	_, err := send(ctx, "POST", "/localapi/v0/set-dns?"+v.Encode(), 200, nil)
	return err
}

// CurrentDERPMap returns the current DERPMap that is being used by the local tailscaled.
// It is intended to be used with netcheck to see availability of DERPs.
func CurrentDERPMap(ctx context.Context) (*tailcfg.DERPMap, error) {
	var derpMap tailcfg.DERPMap
	res, err := send(ctx, "GET", "/localapi/v0/derpmap", 200, nil)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(res, &derpMap); err != nil {
		return nil, fmt.Errorf("invalid derp map json: %w", err)
	}
	return &derpMap, nil
}

// CertPair returns a cert and private key for the provided DNS domain.
//
// It returns a cached certificate from disk if it's still valid.
func CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	res, err := send(ctx, "GET", "/localapi/v0/cert/"+domain+"?type=pair", 200, nil)
	if err != nil {
		return nil, nil, err
	}
	// with ?type=pair, the response PEM is first the one private
	// key PEM block, then the cert PEM blocks.
	i := mem.Index(mem.B(res), mem.S("--\n--"))
	if i == -1 {
		return nil, nil, fmt.Errorf("unexpected output: no delimiter")
	}
	i += len("--\n")
	keyPEM, certPEM = res[:i], res[i:]
	if mem.Contains(mem.B(certPEM), mem.S(" PRIVATE KEY-----")) {
		return nil, nil, fmt.Errorf("unexpected output: key in cert")
	}
	return certPEM, keyPEM, nil
}

// GetCertificate fetches a TLS certificate for the TLS ClientHello in hi.
//
// It returns a cached certificate from disk if it's still valid.
//
// It's the right signature to use as the value of
// tls.Config.GetCertificate.
func GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi == nil || hi.ServerName == "" {
		return nil, errors.New("no SNI ServerName")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	name := hi.ServerName
	if !strings.Contains(name, ".") {
		if v, ok := ExpandSNIName(ctx, name); ok {
			name = v
		}
	}
	certPEM, keyPEM, err := CertPair(ctx, name)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// ExpandSNIName expands bare label name into the the most likely actual TLS cert name.
func ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	st, err := StatusWithoutPeers(ctx)
	if err != nil {
		return "", false
	}
	for _, d := range st.CertDomains {
		if len(d) > len(name)+1 && strings.HasPrefix(d, name) && d[len(name)] == '.' {
			return d, true
		}
	}
	return "", false
}

// tailscaledConnectHint gives a little thing about why tailscaled (or
// platform equivalent) is not answering localapi connections.
//
// It ends in a punctuation. See caller.
func tailscaledConnectHint() string {
	if runtime.GOOS != "linux" {
		// TODO(bradfitz): flesh this out
		return "not running?"
	}
	out, err := exec.Command("systemctl", "show", "tailscaled.service", "--no-page", "--property", "LoadState,ActiveState,SubState").Output()
	if err != nil {
		return "not running?"
	}
	// Parse:
	// LoadState=loaded
	// ActiveState=inactive
	// SubState=dead
	st := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, "="); i != -1 {
			st[line[:i]] = strings.TrimSpace(line[i+1:])
		}
	}
	if st["LoadState"] == "loaded" &&
		(st["SubState"] != "running" || st["ActiveState"] != "active") {
		return "systemd tailscaled.service not running."
	}
	return "not running?"
}
