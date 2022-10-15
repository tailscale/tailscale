// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

package tailscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
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
	"tailscale.com/net/netutil"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
)

// defaultLocalClient is the default LocalClient when using the legacy
// package-level functions.
var defaultLocalClient LocalClient

// LocalClient is a client to Tailscale's "local API", communicating with the
// Tailscale daemon on the local machine. Its API is not necessarily stable and
// subject to changes between releases. Some API calls have stricter
// compatibility guarantees, once they've been widely adopted. See method docs
// for details.
//
// Its zero value is valid to use.
//
// Any exported fields should be set before using methods on the type
// and not changed thereafter.
type LocalClient struct {
	// Dial optionally specifies an alternate func that connects to the local
	// machine's tailscaled or equivalent. If nil, a default is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Socket specifies an alternate path to the local Tailscale socket.
	// If empty, a platform-specific default is used.
	Socket string

	// UseSocketOnly, if true, tries to only connect to tailscaled via the
	// Unix socket and not via fallback mechanisms as done on macOS when
	// connecting to the GUI client variants.
	UseSocketOnly bool

	// tsClient does HTTP requests to the local Tailscale daemon.
	// It's lazily initialized on first use.
	tsClient     *http.Client
	tsClientOnce sync.Once
}

func (lc *LocalClient) socket() string {
	if lc.Socket != "" {
		return lc.Socket
	}
	return paths.DefaultTailscaledSocket()
}

func (lc *LocalClient) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if lc.Dial != nil {
		return lc.Dial
	}
	return lc.defaultDialer
}

func (lc *LocalClient) defaultDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != "local-tailscaled.sock:80" {
		return nil, fmt.Errorf("unexpected URL address %q", addr)
	}
	if !lc.UseSocketOnly {
		// On macOS, when dialing from non-sandboxed program to sandboxed GUI running
		// a TCP server on a random port, find the random port. For HTTP connections,
		// we don't send the token. It gets added in an HTTP Basic-Auth header.
		if port, _, err := safesocket.LocalTCPPortAndToken(); err == nil {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "localhost:"+strconv.Itoa(port))
		}
	}
	s := safesocket.DefaultConnectionStrategy(lc.socket())
	// The user provided a non-default tailscaled socket address.
	// Connect only to exactly what they provided.
	s.UseFallback(false)
	return safesocket.Connect(s)
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
func (lc *LocalClient) DoLocalRequest(req *http.Request) (*http.Response, error) {
	lc.tsClientOnce.Do(func() {
		lc.tsClient = &http.Client{
			Transport: &http.Transport{
				DialContext: lc.dialer(),
			},
		}
	})
	if _, token, err := safesocket.LocalTCPPortAndToken(); err == nil {
		req.SetBasicAuth("", token)
	}
	return lc.tsClient.Do(req)
}

func (lc *LocalClient) doLocalRequestNiceError(req *http.Request) (*http.Response, error) {
	res, err := lc.DoLocalRequest(req)
	if err == nil {
		if server := res.Header.Get("Tailscale-Version"); server != "" && server != ipn.IPCVersion() && onVersionMismatch != nil {
			onVersionMismatch(ipn.IPCVersion(), server)
		}
		if res.StatusCode == 403 {
			all, _ := io.ReadAll(res.Body)
			return nil, &AccessDeniedError{errors.New(errorMessageFromBody(all))}
		}
		return res, nil
	}
	if ue, ok := err.(*url.Error); ok {
		if oe, ok := ue.Err.(*net.OpError); ok && oe.Op == "dial" {
			path := req.URL.Path
			pathPrefix, _, _ := strings.Cut(path, "?")
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

func (lc *LocalClient) send(ctx context.Context, method, path string, wantStatus int, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://local-tailscaled.sock"+path, body)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != wantStatus {
		err = fmt.Errorf("%v: %s", res.Status, bytes.TrimSpace(slurp))
		return nil, bestError(err, slurp)
	}
	return slurp, nil
}

func (lc *LocalClient) get200(ctx context.Context, path string) ([]byte, error) {
	return lc.send(ctx, "GET", path, 200, nil)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
//
// Deprecated: use LocalClient.WhoIs.
func WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return defaultLocalClient.WhoIs(ctx, remoteAddr)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
func (lc *LocalClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr))
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
func (lc *LocalClient) Goroutines(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/goroutines")
}

// DaemonMetrics returns the Tailscale daemon's metrics in
// the Prometheus text exposition format.
func (lc *LocalClient) DaemonMetrics(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/metrics")
}

// Profile returns a pprof profile of the Tailscale daemon.
func (lc *LocalClient) Profile(ctx context.Context, pprofType string, sec int) ([]byte, error) {
	var secArg string
	if sec < 0 || sec > 300 {
		return nil, errors.New("duration out of range")
	}
	if sec != 0 || pprofType == "profile" {
		secArg = fmt.Sprint(sec)
	}
	return lc.get200(ctx, fmt.Sprintf("/localapi/v0/profile?name=%s&seconds=%v", url.QueryEscape(pprofType), secArg))
}

// BugReportOpts contains options to pass to the Tailscale daemon when
// generating a bug report.
type BugReportOpts struct {
	// Note contains an optional user-provided note to add to the logs.
	Note string

	// Diagnose specifies whether to print additional diagnostic information to
	// the logs when generating this bugreport.
	Diagnose bool

	// Record specifies, if non-nil, whether to perform a bugreport
	// "recording"–generating an initial log marker, then waiting for
	// this channel to be closed before finishing the request, which
	// generates another log marker.
	Record <-chan struct{}
}

// BugReportWithOpts logs and returns a log marker that can be shared by the
// user with support.
//
// The opts type specifies options to pass to the Tailscale daemon when
// generating this bug report.
func (lc *LocalClient) BugReportWithOpts(ctx context.Context, opts BugReportOpts) (string, error) {
	qparams := make(url.Values)
	if opts.Note != "" {
		qparams.Set("note", opts.Note)
	}
	if opts.Diagnose {
		qparams.Set("diagnose", "true")
	}
	if opts.Record != nil {
		qparams.Set("record", "true")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var requestBody io.Reader
	if opts.Record != nil {
		pr, pw := io.Pipe()
		requestBody = pr

		// This goroutine waits for the 'Record' channel to be closed,
		// and then closes the write end of our pipe to unblock the
		// reader.
		go func() {
			defer pw.Close()
			select {
			case <-opts.Record:
			case <-ctx.Done():
			}
		}()
	}

	// lc.send might block if opts.Record != nil; see above.
	uri := fmt.Sprintf("/localapi/v0/bugreport?%s", qparams.Encode())
	body, err := lc.send(ctx, "POST", uri, 200, requestBody)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// BugReport logs and returns a log marker that can be shared by the user with support.
//
// This is the same as calling BugReportWithOpts and only specifying the Note
// field.
func (lc *LocalClient) BugReport(ctx context.Context, note string) (string, error) {
	return lc.BugReportWithOpts(ctx, BugReportOpts{Note: note})
}

// DebugAction invokes a debug action, such as "rebind" or "restun".
// These are development tools and subject to change or removal over time.
func (lc *LocalClient) DebugAction(ctx context.Context, action string) error {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug?action="+url.QueryEscape(action), 200, nil)
	if err != nil {
		return fmt.Errorf("error %w: %s", err, body)
	}
	return nil
}

// SetComponentDebugLogging sets component's debug logging enabled for
// the provided duration. If the duration is in the past, the debug logging
// is disabled.
func (lc *LocalClient) SetComponentDebugLogging(ctx context.Context, component string, d time.Duration) error {
	body, err := lc.send(ctx, "POST",
		fmt.Sprintf("/localapi/v0/component-debug-logging?component=%s&secs=%d",
			url.QueryEscape(component), int64(d.Seconds())), 200, nil)
	if err != nil {
		return fmt.Errorf("error %w: %s", err, body)
	}
	var res struct {
		Error string
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return err
	}
	if res.Error != "" {
		return errors.New(res.Error)
	}
	return nil
}

// Status returns the Tailscale daemon's status.
func Status(ctx context.Context) (*ipnstate.Status, error) {
	return defaultLocalClient.Status(ctx)
}

// Status returns the Tailscale daemon's status.
func (lc *LocalClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	return lc.status(ctx, "")
}

// StatusWithoutPeers returns the Tailscale daemon's status, without the peer info.
func StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return defaultLocalClient.StatusWithoutPeers(ctx)
}

// StatusWithoutPeers returns the Tailscale daemon's status, without the peer info.
func (lc *LocalClient) StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return lc.status(ctx, "?peers=false")
}

func (lc *LocalClient) status(ctx context.Context, queryString string) (*ipnstate.Status, error) {
	body, err := lc.get200(ctx, "/localapi/v0/status"+queryString)
	if err != nil {
		return nil, err
	}
	st := new(ipnstate.Status)
	if err := json.Unmarshal(body, st); err != nil {
		return nil, err
	}
	return st, nil
}

// IDToken is a request to get an OIDC ID token for an audience.
// The token can be presented to any resource provider which offers OIDC
// Federation.
func (lc *LocalClient) IDToken(ctx context.Context, aud string) (*tailcfg.TokenResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/id-token?aud="+url.QueryEscape(aud))
	if err != nil {
		return nil, err
	}
	tr := new(tailcfg.TokenResponse)
	if err := json.Unmarshal(body, tr); err != nil {
		return nil, err
	}
	return tr, nil
}

func (lc *LocalClient) WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	body, err := lc.get200(ctx, "/localapi/v0/files/")
	if err != nil {
		return nil, err
	}
	var wfs []apitype.WaitingFile
	if err := json.Unmarshal(body, &wfs); err != nil {
		return nil, err
	}
	return wfs, nil
}

func (lc *LocalClient) DeleteWaitingFile(ctx context.Context, baseName string) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/files/"+url.PathEscape(baseName), http.StatusNoContent, nil)
	return err
}

func (lc *LocalClient) GetWaitingFile(ctx context.Context, baseName string) (rc io.ReadCloser, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://local-tailscaled.sock/localapi/v0/files/"+url.PathEscape(baseName), nil)
	if err != nil {
		return nil, 0, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, 0, err
	}
	if res.ContentLength == -1 {
		res.Body.Close()
		return nil, 0, fmt.Errorf("unexpected chunking")
	}
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, 0, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}
	return res.Body, res.ContentLength, nil
}

func (lc *LocalClient) FileTargets(ctx context.Context) ([]apitype.FileTarget, error) {
	body, err := lc.get200(ctx, "/localapi/v0/file-targets")
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
func (lc *LocalClient) PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://local-tailscaled.sock/localapi/v0/file-put/"+string(target)+"/"+url.PathEscape(name), r)
	if err != nil {
		return err
	}
	if size != -1 {
		req.ContentLength = size
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return err
	}
	if res.StatusCode == 200 {
		io.Copy(io.Discard, res.Body)
		return nil
	}
	all, _ := io.ReadAll(res.Body)
	return bestError(fmt.Errorf("%s: %s", res.Status, all), all)
}

// CheckIPForwarding asks the local Tailscale daemon whether it looks like the
// machine is properly configured to forward IP packets as a subnet router
// or exit node.
func (lc *LocalClient) CheckIPForwarding(ctx context.Context) error {
	body, err := lc.get200(ctx, "/localapi/v0/check-ip-forwarding")
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

// CheckPrefs validates the provided preferences, without making any changes.
//
// The CLI uses this before a Start call to fail fast if the preferences won't
// work. Currently (2022-04-18) this only checks for SSH server compatibility.
// Note that EditPrefs does the same validation as this, so call CheckPrefs before
// EditPrefs is not necessary.
func (lc *LocalClient) CheckPrefs(ctx context.Context, p *ipn.Prefs) error {
	pj, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = lc.send(ctx, "POST", "/localapi/v0/check-prefs", http.StatusOK, bytes.NewReader(pj))
	return err
}

func (lc *LocalClient) GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
	body, err := lc.get200(ctx, "/localapi/v0/prefs")
	if err != nil {
		return nil, err
	}
	var p ipn.Prefs
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid prefs JSON: %w", err)
	}
	return &p, nil
}

func (lc *LocalClient) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	mpj, err := json.Marshal(mp)
	if err != nil {
		return nil, err
	}
	body, err := lc.send(ctx, "PATCH", "/localapi/v0/prefs", http.StatusOK, bytes.NewReader(mpj))
	if err != nil {
		return nil, err
	}
	var p ipn.Prefs
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("invalid prefs JSON: %w", err)
	}
	return &p, nil
}

func (lc *LocalClient) Logout(ctx context.Context) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/logout", http.StatusNoContent, nil)
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
func (lc *LocalClient) SetDNS(ctx context.Context, name, value string) error {
	v := url.Values{}
	v.Set("name", name)
	v.Set("value", value)
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-dns?"+v.Encode(), 200, nil)
	return err
}

// DialTCP connects to the host's port via Tailscale.
//
// The host may be a base DNS name (resolved from the netmap inside
// tailscaled), a FQDN, or an IP address.
//
// The ctx is only used for the duration of the call, not the lifetime of the net.Conn.
func (lc *LocalClient) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			connCh <- info.Conn
		},
	}
	ctx = httptrace.WithClientTrace(ctx, &trace)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://local-tailscaled.sock/localapi/v0/dial", nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"Upgrade":    []string{"ts-dial"},
		"Connection": []string{"upgrade"},
		"Dial-Host":  []string{host},
		"Dial-Port":  []string{fmt.Sprint(port)},
	}
	res, err := lc.DoLocalRequest(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP response: %s, %s", res.Status, body)
	}
	// From here on, the underlying net.Conn is ours to use, but there
	// is still a read buffer attached to it within resp.Body. So, we
	// must direct I/O through resp.Body, but we can still use the
	// underlying net.Conn for stuff like deadlines.
	var switchedConn net.Conn
	select {
	case switchedConn = <-connCh:
	default:
	}
	if switchedConn == nil {
		res.Body.Close()
		return nil, fmt.Errorf("httptrace didn't provide a connection")
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		res.Body.Close()
		return nil, errors.New("http Transport did not provide a writable body")
	}
	return netutil.NewAltReadWriteCloserConn(rwc, switchedConn), nil
}

// CurrentDERPMap returns the current DERPMap that is being used by the local tailscaled.
// It is intended to be used with netcheck to see availability of DERPs.
func (lc *LocalClient) CurrentDERPMap(ctx context.Context) (*tailcfg.DERPMap, error) {
	var derpMap tailcfg.DERPMap
	res, err := lc.send(ctx, "GET", "/localapi/v0/derpmap", 200, nil)
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
//
// Deprecated: use LocalClient.CertPair.
func CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	return defaultLocalClient.CertPair(ctx, domain)
}

// CertPair returns a cert and private key for the provided DNS domain.
//
// It returns a cached certificate from disk if it's still valid.
//
// API maturity: this is considered a stable API.
func (lc *LocalClient) CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	res, err := lc.send(ctx, "GET", "/localapi/v0/cert/"+domain+"?type=pair", 200, nil)
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
//
// Deprecated: use LocalClient.GetCertificate.
func GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return defaultLocalClient.GetCertificate(hi)
}

// GetCertificate fetches a TLS certificate for the TLS ClientHello in hi.
//
// It returns a cached certificate from disk if it's still valid.
//
// It's the right signature to use as the value of
// tls.Config.GetCertificate.
//
// API maturity: this is considered a stable API.
func (lc *LocalClient) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi == nil || hi.ServerName == "" {
		return nil, errors.New("no SNI ServerName")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	name := hi.ServerName
	if !strings.Contains(name, ".") {
		if v, ok := lc.ExpandSNIName(ctx, name); ok {
			name = v
		}
	}
	certPEM, keyPEM, err := lc.CertPair(ctx, name)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// ExpandSNIName expands bare label name into the most likely actual TLS cert name.
//
// Deprecated: use LocalClient.ExpandSNIName.
func ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	return defaultLocalClient.ExpandSNIName(ctx, name)
}

// ExpandSNIName expands bare label name into the most likely actual TLS cert name.
func (lc *LocalClient) ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	st, err := lc.StatusWithoutPeers(ctx)
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

// Ping sends a ping of the provided type to the provided IP and waits
// for its response.
func (lc *LocalClient) Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error) {
	v := url.Values{}
	v.Set("ip", ip.String())
	v.Set("type", string(pingtype))
	body, err := lc.send(ctx, "POST", "/localapi/v0/ping?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	pr := new(ipnstate.PingResult)
	if err := json.Unmarshal(body, pr); err != nil {
		return nil, err
	}
	return pr, nil
}

// NetworkLockStatus fetches information about the tailnet key authority, if one is configured.
func (lc *LocalClient) NetworkLockStatus(ctx context.Context) (*ipnstate.NetworkLockStatus, error) {
	body, err := lc.send(ctx, "GET", "/localapi/v0/tka/status", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	pr := new(ipnstate.NetworkLockStatus)
	if err := json.Unmarshal(body, pr); err != nil {
		return nil, err
	}
	return pr, nil
}

// NetworkLockInit initializes the tailnet key authority.
func (lc *LocalClient) NetworkLockInit(ctx context.Context, keys []tka.Key) (*ipnstate.NetworkLockStatus, error) {
	var b bytes.Buffer
	type initRequest struct {
		Keys []tka.Key
	}

	if err := json.NewEncoder(&b).Encode(initRequest{Keys: keys}); err != nil {
		return nil, err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/init", 200, &b)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	pr := new(ipnstate.NetworkLockStatus)
	if err := json.Unmarshal(body, pr); err != nil {
		return nil, err
	}
	return pr, nil
}

// NetworkLockModify adds and/or removes key(s) to the tailnet key authority.
func (lc *LocalClient) NetworkLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) (*ipnstate.NetworkLockStatus, error) {
	var b bytes.Buffer
	type modifyRequest struct {
		AddKeys    []tka.Key
		RemoveKeys []tka.Key
	}

	if err := json.NewEncoder(&b).Encode(modifyRequest{AddKeys: addKeys, RemoveKeys: removeKeys}); err != nil {
		return nil, err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/modify", 200, &b)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}

	pr := new(ipnstate.NetworkLockStatus)
	if err := json.Unmarshal(body, pr); err != nil {
		return nil, err
	}
	return pr, nil
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
		if k, v, ok := strings.Cut(line, "="); ok {
			st[k] = strings.TrimSpace(v)
		}
	}
	if st["LoadState"] == "loaded" &&
		(st["SubState"] != "running" || st["ActiveState"] != "active") {
		return "systemd tailscaled.service not running."
	}
	return "not running?"
}
