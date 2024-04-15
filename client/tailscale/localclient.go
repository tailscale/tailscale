// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"bytes"
	"cmp"
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
	"tailscale.com/drive"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netutil"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// defaultLocalClient is the default LocalClient when using the legacy
// package-level functions.
var defaultLocalClient LocalClient

// LocalClient is a client to Tailscale's "LocalAPI", communicating with the
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
			// We use 127.0.0.1 and not "localhost" (issue 7851).
			var d net.Dialer
			return d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(port))
		}
	}
	return safesocket.Connect(lc.socket())
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
	req.Header.Set("Tailscale-Cap", strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
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
		if server := res.Header.Get("Tailscale-Version"); server != "" && server != envknob.IPCVersion() && onVersionMismatch != nil {
			onVersionMismatch(envknob.IPCVersion(), server)
		}
		if res.StatusCode == 403 {
			all, _ := io.ReadAll(res.Body)
			return nil, &AccessDeniedError{errors.New(errorMessageFromBody(all))}
		}
		if res.StatusCode == http.StatusPreconditionFailed {
			all, _ := io.ReadAll(res.Body)
			return nil, &PreconditionsFailedError{errors.New(errorMessageFromBody(all))}
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

// PreconditionsFailedError is returned when the server responds
// with an HTTP 412 status code.
type PreconditionsFailedError struct {
	err error
}

func (e *PreconditionsFailedError) Error() string {
	return fmt.Sprintf("Preconditions failed: %v", e.err)
}

func (e *PreconditionsFailedError) Unwrap() error { return e.err }

// IsPreconditionsFailedError reports whether err is or wraps an PreconditionsFailedError.
func IsPreconditionsFailedError(err error) bool {
	var ae *PreconditionsFailedError
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
	slurp, _, err := lc.sendWithHeaders(ctx, method, path, wantStatus, body, nil)
	return slurp, err
}

func (lc *LocalClient) sendWithHeaders(
	ctx context.Context,
	method,
	path string,
	wantStatus int,
	body io.Reader,
	h http.Header,
) ([]byte, http.Header, error) {
	if jr, ok := body.(jsonReader); ok && jr.err != nil {
		return nil, nil, jr.err // fail early if there was a JSON marshaling error
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+apitype.LocalAPIHost+path, body)
	if err != nil {
		return nil, nil, err
	}
	if h != nil {
		req.Header = h
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	if res.StatusCode != wantStatus {
		err = fmt.Errorf("%v: %s", res.Status, bytes.TrimSpace(slurp))
		return nil, nil, bestError(err, slurp)
	}
	return slurp, res.Header, nil
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

func decodeJSON[T any](b []byte) (ret T, err error) {
	if err := json.Unmarshal(b, &ret); err != nil {
		var zero T
		return zero, fmt.Errorf("failed to unmarshal JSON into %T: %w", ret, err)
	}
	return ret, nil
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
func (lc *LocalClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr))
	if err != nil {
		return nil, err
	}
	return decodeJSON[*apitype.WhoIsResponse](body)
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

// IncrementCounter increments the value of a Tailscale daemon's counter
// metric by the given delta. If the metric has yet to exist, a new counter
// metric is created and initialized to delta.
//
// IncrementCounter does not support gauge metrics or negative delta values.
func (lc *LocalClient) IncrementCounter(ctx context.Context, name string, delta int) error {
	type metricUpdate struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value int    `json:"value"` // amount to increment by
	}
	if delta < 0 {
		return errors.New("negative delta not allowed")
	}
	_, err := lc.send(ctx, "POST", "/localapi/v0/upload-client-metrics", 200, jsonBody([]metricUpdate{{
		Name:  name,
		Type:  "counter",
		Value: delta,
	}}))
	return err
}

// TailDaemonLogs returns a stream the Tailscale daemon's logs as they arrive.
// Close the context to stop the stream.
func (lc *LocalClient) TailDaemonLogs(ctx context.Context) (io.Reader, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+apitype.LocalAPIHost+"/localapi/v0/logtap", nil)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}
	return res.Body, nil
}

// Pprof returns a pprof profile of the Tailscale daemon.
func (lc *LocalClient) Pprof(ctx context.Context, pprofType string, sec int) ([]byte, error) {
	var secArg string
	if sec < 0 || sec > 300 {
		return nil, errors.New("duration out of range")
	}
	if sec != 0 || pprofType == "profile" {
		secArg = fmt.Sprint(sec)
	}
	return lc.get200(ctx, fmt.Sprintf("/localapi/v0/pprof?name=%s&seconds=%v", url.QueryEscape(pprofType), secArg))
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

// DebugResultJSON invokes a debug action and returns its result as something JSON-able.
// These are development tools and subject to change or removal over time.
func (lc *LocalClient) DebugResultJSON(ctx context.Context, action string) (any, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug?action="+url.QueryEscape(action), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	var x any
	if err := json.Unmarshal(body, &x); err != nil {
		return nil, err
	}
	return x, nil
}

// DebugPortmapOpts contains options for the DebugPortmap command.
type DebugPortmapOpts struct {
	// Duration is how long the mapping should be created for. It defaults
	// to 5 seconds if not set.
	Duration time.Duration

	// Type is the kind of portmap to debug. The empty string instructs the
	// portmap client to perform all known types. Other valid options are
	// "pmp", "pcp", and "upnp".
	Type string

	// GatewayAddr specifies the gateway address used during portmapping.
	// If set, SelfAddr must also be set. If unset, it will be
	// autodetected.
	GatewayAddr netip.Addr

	// SelfAddr specifies the gateway address used during portmapping. If
	// set, GatewayAddr must also be set. If unset, it will be
	// autodetected.
	SelfAddr netip.Addr

	// LogHTTP instructs the debug-portmap endpoint to print all HTTP
	// requests and responses made to the logs.
	LogHTTP bool
}

// DebugPortmap invokes the debug-portmap endpoint, and returns an
// io.ReadCloser that can be used to read the logs that are printed during this
// process.
//
// opts can be nil; if so, default values will be used.
func (lc *LocalClient) DebugPortmap(ctx context.Context, opts *DebugPortmapOpts) (io.ReadCloser, error) {
	vals := make(url.Values)
	if opts == nil {
		opts = &DebugPortmapOpts{}
	}

	vals.Set("duration", cmp.Or(opts.Duration, 5*time.Second).String())
	vals.Set("type", opts.Type)
	vals.Set("log_http", strconv.FormatBool(opts.LogHTTP))

	if opts.GatewayAddr.IsValid() != opts.SelfAddr.IsValid() {
		return nil, fmt.Errorf("both GatewayAddr and SelfAddr must be provided if one is")
	} else if opts.GatewayAddr.IsValid() {
		vals.Set("gateway_and_self", fmt.Sprintf("%s/%s", opts.GatewayAddr, opts.SelfAddr))
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+apitype.LocalAPIHost+"/localapi/v0/debug-portmap?"+vals.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return nil, fmt.Errorf("HTTP %s: %s", res.Status, body)
	}

	return res.Body, nil
}

// SetDevStoreKeyValue set a statestore key/value. It's only meant for development.
// The schema (including when keys are re-read) is not a stable interface.
func (lc *LocalClient) SetDevStoreKeyValue(ctx context.Context, key, value string) error {
	body, err := lc.send(ctx, "POST", "/localapi/v0/dev-set-state-store?"+(url.Values{
		"key":   {key},
		"value": {value},
	}).Encode(), 200, nil)
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
	return decodeJSON[*ipnstate.Status](body)
}

// IDToken is a request to get an OIDC ID token for an audience.
// The token can be presented to any resource provider which offers OIDC
// Federation.
func (lc *LocalClient) IDToken(ctx context.Context, aud string) (*tailcfg.TokenResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/id-token?aud="+url.QueryEscape(aud))
	if err != nil {
		return nil, err
	}
	return decodeJSON[*tailcfg.TokenResponse](body)
}

// WaitingFiles returns the list of received Taildrop files that have been
// received by the Tailscale daemon in its staging/cache directory but not yet
// transferred by the user's CLI or GUI client and written to a user's home
// directory somewhere.
func (lc *LocalClient) WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	return lc.AwaitWaitingFiles(ctx, 0)
}

// AwaitWaitingFiles is like WaitingFiles but takes a duration to await for an answer.
// If the duration is 0, it will return immediately. The duration is respected at second
// granularity only. If no files are available, it returns (nil, nil).
func (lc *LocalClient) AwaitWaitingFiles(ctx context.Context, d time.Duration) ([]apitype.WaitingFile, error) {
	path := "/localapi/v0/files/?waitsec=" + fmt.Sprint(int(d.Seconds()))
	body, err := lc.get200(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]apitype.WaitingFile](body)
}

func (lc *LocalClient) DeleteWaitingFile(ctx context.Context, baseName string) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/files/"+url.PathEscape(baseName), http.StatusNoContent, nil)
	return err
}

func (lc *LocalClient) GetWaitingFile(ctx context.Context, baseName string) (rc io.ReadCloser, size int64, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+apitype.LocalAPIHost+"/localapi/v0/files/"+url.PathEscape(baseName), nil)
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
	return decodeJSON[[]apitype.FileTarget](body)
}

// PushFile sends Taildrop file r to target.
//
// A size of -1 means unknown.
// The name parameter is the original filename, not escaped.
func (lc *LocalClient) PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, "PUT", "http://"+apitype.LocalAPIHost+"/localapi/v0/file-put/"+string(target)+"/"+url.PathEscape(name), r)
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

// CheckUDPGROForwarding asks the local Tailscale daemon whether it looks like
// the machine is optimally configured to forward UDP packets as a subnet router
// or exit node.
func (lc *LocalClient) CheckUDPGROForwarding(ctx context.Context) error {
	body, err := lc.get200(ctx, "/localapi/v0/check-udp-gro-forwarding")
	if err != nil {
		return err
	}
	var jres struct {
		Warning string
	}
	if err := json.Unmarshal(body, &jres); err != nil {
		return fmt.Errorf("invalid JSON from check-udp-gro-forwarding: %w", err)
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
	_, err := lc.send(ctx, "POST", "/localapi/v0/check-prefs", http.StatusOK, jsonBody(p))
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
	body, err := lc.send(ctx, "PATCH", "/localapi/v0/prefs", http.StatusOK, jsonBody(mp))
	if err != nil {
		return nil, err
	}
	return decodeJSON[*ipn.Prefs](body)
}

// StartLoginInteractive starts an interactive login.
func (lc *LocalClient) StartLoginInteractive(ctx context.Context) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/login-interactive", http.StatusNoContent, nil)
	return err
}

// Start applies the configuration specified in opts, and starts the
// state machine.
func (lc *LocalClient) Start(ctx context.Context, opts ipn.Options) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/start", http.StatusNoContent, jsonBody(opts))
	return err
}

// Logout logs out the current node.
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
	req, err := http.NewRequestWithContext(ctx, "POST", "http://"+apitype.LocalAPIHost+"/localapi/v0/dial", nil)
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

// PingOpts contains options for the ping request.
//
// The zero value is valid, which means to use defaults.
type PingOpts struct {
	// Size is the length of the ping message in bytes. It's ignored if it's
	// smaller than the minimum message size.
	//
	// For disco pings, it specifies the length of the packet's payload. That
	// is, it includes the disco headers and message, but not the IP and UDP
	// headers.
	Size int
}

// Ping sends a ping of the provided type to the provided IP and waits
// for its response. The opts type specifies additional options.
func (lc *LocalClient) PingWithOpts(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType, opts PingOpts) (*ipnstate.PingResult, error) {
	v := url.Values{}
	v.Set("ip", ip.String())
	v.Set("size", strconv.Itoa(opts.Size))
	v.Set("type", string(pingtype))
	body, err := lc.send(ctx, "POST", "/localapi/v0/ping?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*ipnstate.PingResult](body)
}

// Ping sends a ping of the provided type to the provided IP and waits
// for its response.
func (lc *LocalClient) Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error) {
	return lc.PingWithOpts(ctx, ip, pingtype, PingOpts{})
}

// NetworkLockStatus fetches information about the tailnet key authority, if one is configured.
func (lc *LocalClient) NetworkLockStatus(ctx context.Context) (*ipnstate.NetworkLockStatus, error) {
	body, err := lc.send(ctx, "GET", "/localapi/v0/tka/status", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[*ipnstate.NetworkLockStatus](body)
}

// NetworkLockInit initializes the tailnet key authority.
//
// TODO(tom): Plumb through disablement secrets.
func (lc *LocalClient) NetworkLockInit(ctx context.Context, keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) (*ipnstate.NetworkLockStatus, error) {
	var b bytes.Buffer
	type initRequest struct {
		Keys               []tka.Key
		DisablementValues  [][]byte
		SupportDisablement []byte
	}

	if err := json.NewEncoder(&b).Encode(initRequest{Keys: keys, DisablementValues: disablementValues, SupportDisablement: supportDisablement}); err != nil {
		return nil, err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/init", 200, &b)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[*ipnstate.NetworkLockStatus](body)
}

// NetworkLockWrapPreauthKey wraps a pre-auth key with information to
// enable unattended bringup in the locked tailnet.
func (lc *LocalClient) NetworkLockWrapPreauthKey(ctx context.Context, preauthKey string, tkaKey key.NLPrivate) (string, error) {
	encodedPrivate, err := tkaKey.MarshalText()
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	type wrapRequest struct {
		TSKey  string
		TKAKey string // key.NLPrivate.MarshalText
	}
	if err := json.NewEncoder(&b).Encode(wrapRequest{TSKey: preauthKey, TKAKey: string(encodedPrivate)}); err != nil {
		return "", err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/wrap-preauth-key", 200, &b)
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}
	return string(body), nil
}

// NetworkLockModify adds and/or removes key(s) to the tailnet key authority.
func (lc *LocalClient) NetworkLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) error {
	var b bytes.Buffer
	type modifyRequest struct {
		AddKeys    []tka.Key
		RemoveKeys []tka.Key
	}

	if err := json.NewEncoder(&b).Encode(modifyRequest{AddKeys: addKeys, RemoveKeys: removeKeys}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/modify", 204, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// NetworkLockSign signs the specified node-key and transmits that signature to the control plane.
// rotationPublic, if specified, must be an ed25519 public key.
func (lc *LocalClient) NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error {
	var b bytes.Buffer
	type signRequest struct {
		NodeKey        key.NodePublic
		RotationPublic []byte
	}

	if err := json.NewEncoder(&b).Encode(signRequest{NodeKey: nodeKey, RotationPublic: rotationPublic}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/sign", 200, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// NetworkLockAffectedSigs returns all signatures signed by the specified keyID.
func (lc *LocalClient) NetworkLockAffectedSigs(ctx context.Context, keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/affected-sigs", 200, bytes.NewReader(keyID))
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[[]tkatype.MarshaledSignature](body)
}

// NetworkLockLog returns up to maxEntries number of changes to network-lock state.
func (lc *LocalClient) NetworkLockLog(ctx context.Context, maxEntries int) ([]ipnstate.NetworkLockUpdate, error) {
	v := url.Values{}
	v.Set("limit", fmt.Sprint(maxEntries))
	body, err := lc.send(ctx, "GET", "/localapi/v0/tka/log?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[[]ipnstate.NetworkLockUpdate](body)
}

// NetworkLockForceLocalDisable forcibly shuts down network lock on this node.
func (lc *LocalClient) NetworkLockForceLocalDisable(ctx context.Context) error {
	// This endpoint expects an empty JSON stanza as the payload.
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(struct{}{}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/force-local-disable", 200, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// NetworkLockVerifySigningDeeplink verifies the network lock deeplink contained
// in url and returns information extracted from it.
func (lc *LocalClient) NetworkLockVerifySigningDeeplink(ctx context.Context, url string) (*tka.DeeplinkValidationResult, error) {
	vr := struct {
		URL string
	}{url}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/verify-deeplink", 200, jsonBody(vr))
	if err != nil {
		return nil, fmt.Errorf("sending verify-deeplink: %w", err)
	}

	return decodeJSON[*tka.DeeplinkValidationResult](body)
}

// NetworkLockGenRecoveryAUM generates an AUM for recovering from a tailnet-lock key compromise.
func (lc *LocalClient) NetworkLockGenRecoveryAUM(ctx context.Context, removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) ([]byte, error) {
	vr := struct {
		Keys     []tkatype.KeyID
		ForkFrom string
	}{removeKeys, forkFrom.String()}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/generate-recovery-aum", 200, jsonBody(vr))
	if err != nil {
		return nil, fmt.Errorf("sending generate-recovery-aum: %w", err)
	}

	return body, nil
}

// NetworkLockCosignRecoveryAUM co-signs a recovery AUM using the node's tailnet lock key.
func (lc *LocalClient) NetworkLockCosignRecoveryAUM(ctx context.Context, aum tka.AUM) ([]byte, error) {
	r := bytes.NewReader(aum.Serialize())
	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/cosign-recovery-aum", 200, r)
	if err != nil {
		return nil, fmt.Errorf("sending cosign-recovery-aum: %w", err)
	}

	return body, nil
}

// NetworkLockSubmitRecoveryAUM submits a recovery AUM to the control plane.
func (lc *LocalClient) NetworkLockSubmitRecoveryAUM(ctx context.Context, aum tka.AUM) error {
	r := bytes.NewReader(aum.Serialize())
	_, err := lc.send(ctx, "POST", "/localapi/v0/tka/submit-recovery-aum", 200, r)
	if err != nil {
		return fmt.Errorf("sending cosign-recovery-aum: %w", err)
	}
	return nil
}

// SetServeConfig sets or replaces the serving settings.
// If config is nil, settings are cleared and serving is disabled.
func (lc *LocalClient) SetServeConfig(ctx context.Context, config *ipn.ServeConfig) error {
	h := make(http.Header)
	if config != nil {
		h.Set("If-Match", config.ETag)
	}
	_, _, err := lc.sendWithHeaders(ctx, "POST", "/localapi/v0/serve-config", 200, jsonBody(config), h)
	if err != nil {
		return fmt.Errorf("sending serve config: %w", err)
	}
	return nil
}

// NetworkLockDisable shuts down network-lock across the tailnet.
func (lc *LocalClient) NetworkLockDisable(ctx context.Context, secret []byte) error {
	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/disable", 200, bytes.NewReader(secret)); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// GetServeConfig return the current serve config.
//
// If the serve config is empty, it returns (nil, nil).
func (lc *LocalClient) GetServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	body, h, err := lc.sendWithHeaders(ctx, "GET", "/localapi/v0/serve-config", 200, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("getting serve config: %w", err)
	}
	sc, err := getServeConfigFromJSON(body)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	sc.ETag = h.Get("Etag")
	return sc, nil
}

func getServeConfigFromJSON(body []byte) (sc *ipn.ServeConfig, err error) {
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, err
	}
	return sc, nil
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

type jsonReader struct {
	b   *bytes.Reader
	err error // sticky JSON marshal error, if any
}

// jsonBody returns an io.Reader that marshals v as JSON and then reads it.
func jsonBody(v any) jsonReader {
	b, err := json.Marshal(v)
	if err != nil {
		return jsonReader{err: err}
	}
	return jsonReader{b: bytes.NewReader(b)}
}

func (r jsonReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.b.Read(p)
}

// ProfileStatus returns the current profile and the list of all profiles.
func (lc *LocalClient) ProfileStatus(ctx context.Context) (current ipn.LoginProfile, all []ipn.LoginProfile, err error) {
	body, err := lc.send(ctx, "GET", "/localapi/v0/profiles/current", 200, nil)
	if err != nil {
		return
	}
	current, err = decodeJSON[ipn.LoginProfile](body)
	if err != nil {
		return
	}
	body, err = lc.send(ctx, "GET", "/localapi/v0/profiles/", 200, nil)
	if err != nil {
		return
	}
	all, err = decodeJSON[[]ipn.LoginProfile](body)
	return current, all, err
}

// ReloadConfig reloads the config file, if possible.
func (lc *LocalClient) ReloadConfig(ctx context.Context) (ok bool, err error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/reload-config", 200, nil)
	if err != nil {
		return
	}
	res, err := decodeJSON[apitype.ReloadConfigResponse](body)
	if err != nil {
		return
	}
	if res.Err != "" {
		return false, errors.New(res.Err)
	}
	return res.Reloaded, nil
}

// SwitchToEmptyProfile creates and switches to a new unnamed profile. The new
// profile is not assigned an ID until it is persisted after a successful login.
// In order to login to the new profile, the user must call LoginInteractive.
func (lc *LocalClient) SwitchToEmptyProfile(ctx context.Context) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/profiles/", http.StatusCreated, nil)
	return err
}

// SwitchProfile switches to the given profile.
func (lc *LocalClient) SwitchProfile(ctx context.Context, profile ipn.ProfileID) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/profiles/"+url.PathEscape(string(profile)), 204, nil)
	return err
}

// DeleteProfile removes the profile with the given ID.
// If the profile is the current profile, an empty profile
// will be selected as if SwitchToEmptyProfile was called.
func (lc *LocalClient) DeleteProfile(ctx context.Context, profile ipn.ProfileID) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/profiles"+url.PathEscape(string(profile)), http.StatusNoContent, nil)
	return err
}

// QueryFeature makes a request for instructions on how to enable
// a feature, such as Funnel, for the node's tailnet. If relevant,
// this includes a control server URL the user can visit to enable
// the feature.
//
// If you are looking to use QueryFeature, you'll likely want to
// use cli.enableFeatureInteractive instead, which handles the logic
// of wraping QueryFeature and translating its response into an
// interactive flow for the user, including using the IPN notify bus
// to block until the feature has been enabled.
//
// 2023-08-09: Valid feature values are "serve" and "funnel".
func (lc *LocalClient) QueryFeature(ctx context.Context, feature string) (*tailcfg.QueryFeatureResponse, error) {
	v := url.Values{"feature": {feature}}
	body, err := lc.send(ctx, "POST", "/localapi/v0/query-feature?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*tailcfg.QueryFeatureResponse](body)
}

func (lc *LocalClient) DebugDERPRegion(ctx context.Context, regionIDOrCode string) (*ipnstate.DebugDERPRegionReport, error) {
	v := url.Values{"region": {regionIDOrCode}}
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug-derp-region?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*ipnstate.DebugDERPRegionReport](body)
}

// DebugPacketFilterRules returns the packet filter rules for the current device.
func (lc *LocalClient) DebugPacketFilterRules(ctx context.Context) ([]tailcfg.FilterRule, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug-packet-filter-rules", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[[]tailcfg.FilterRule](body)
}

// DebugSetExpireIn marks the current node key to expire in d.
//
// This is meant primarily for debug and testing.
func (lc *LocalClient) DebugSetExpireIn(ctx context.Context, d time.Duration) error {
	v := url.Values{"expiry": {fmt.Sprint(time.Now().Add(d).Unix())}}
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-expiry-sooner?"+v.Encode(), 200, nil)
	return err
}

// StreamDebugCapture streams a pcap-formatted packet capture.
//
// The provided context does not determine the lifetime of the
// returned io.ReadCloser.
func (lc *LocalClient) StreamDebugCapture(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "http://"+apitype.LocalAPIHost+"/localapi/v0/debug-capture", nil)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, errors.New(res.Status)
	}
	return res.Body, nil
}

// WatchIPNBus subscribes to the IPN notification bus. It returns a watcher
// once the bus is connected successfully.
//
// The context is used for the life of the watch, not just the call to
// WatchIPNBus.
//
// The returned IPNBusWatcher's Close method must be called when done to release
// resources.
//
// A default set of ipn.Notify messages are returned but the set can be modified by mask.
func (lc *LocalClient) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*IPNBusWatcher, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://"+apitype.LocalAPIHost+"/localapi/v0/watch-ipn-bus?mask="+fmt.Sprint(mask),
		nil)
	if err != nil {
		return nil, err
	}
	res, err := lc.doLocalRequestNiceError(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, errors.New(res.Status)
	}
	dec := json.NewDecoder(res.Body)
	return &IPNBusWatcher{
		ctx:     ctx,
		httpRes: res,
		dec:     dec,
	}, nil
}

// CheckUpdate returns a tailcfg.ClientVersion indicating whether or not an update is available
// to be installed via the LocalAPI. In case the LocalAPI can't install updates, it returns a
// ClientVersion that says that we are up to date.
func (lc *LocalClient) CheckUpdate(ctx context.Context) (*tailcfg.ClientVersion, error) {
	body, err := lc.get200(ctx, "/localapi/v0/update/check")
	if err != nil {
		return nil, err
	}
	cv, err := decodeJSON[tailcfg.ClientVersion](body)
	if err != nil {
		return nil, err
	}
	return &cv, nil
}

// SetUseExitNode toggles the use of an exit node on or off.
// To turn it on, there must have been a previously used exit node.
// The most previously used one is reused.
// This is a convenience method for GUIs. To select an actual one, update the prefs.
func (lc *LocalClient) SetUseExitNode(ctx context.Context, on bool) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-use-exit-node-enabled?enabled="+strconv.FormatBool(on), http.StatusOK, nil)
	return err
}

// DriveSetServerAddr instructs Taildrive to use the server at addr to access
// the filesystem. This is used on platforms like Windows and MacOS to let
// Taildrive know to use the file server running in the GUI app.
func (lc *LocalClient) DriveSetServerAddr(ctx context.Context, addr string) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/drive/fileserver-address", http.StatusCreated, strings.NewReader(addr))
	return err
}

// DriveShareSet adds or updates the given share in the list of shares that
// Taildrive will serve to remote nodes. If a share with the same name already
// exists, the existing share is replaced/updated.
func (lc *LocalClient) DriveShareSet(ctx context.Context, share *drive.Share) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/drive/shares", http.StatusCreated, jsonBody(share))
	return err
}

// DriveShareRemove removes the share with the given name from the list of
// shares that Taildrive will serve to remote nodes.
func (lc *LocalClient) DriveShareRemove(ctx context.Context, name string) error {
	_, err := lc.send(
		ctx,
		"DELETE",
		"/localapi/v0/drive/shares",
		http.StatusNoContent,
		strings.NewReader(name))
	return err
}

// DriveShareRename renames the share from old to new name.
func (lc *LocalClient) DriveShareRename(ctx context.Context, oldName, newName string) error {
	_, err := lc.send(
		ctx,
		"POST",
		"/localapi/v0/drive/shares",
		http.StatusNoContent,
		jsonBody([2]string{oldName, newName}))
	return err
}

// DriveShareList returns the list of shares that drive is currently serving
// to remote nodes.
func (lc *LocalClient) DriveShareList(ctx context.Context) ([]*drive.Share, error) {
	result, err := lc.get200(ctx, "/localapi/v0/drive/shares")
	if err != nil {
		return nil, err
	}
	var shares []*drive.Share
	err = json.Unmarshal(result, &shares)
	return shares, err
}

// IPNBusWatcher is an active subscription (watch) of the local tailscaled IPN bus.
// It's returned by LocalClient.WatchIPNBus.
//
// It must be closed when done.
type IPNBusWatcher struct {
	ctx     context.Context // from original WatchIPNBus call
	httpRes *http.Response
	dec     *json.Decoder

	mu     sync.Mutex
	closed bool
}

// Close stops the watcher and releases its resources.
func (w *IPNBusWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.httpRes.Body.Close()
}

// Next returns the next ipn.Notify from the stream.
// If the context from LocalClient.WatchIPNBus is done, that error is returned.
func (w *IPNBusWatcher) Next() (ipn.Notify, error) {
	var n ipn.Notify
	if err := w.dec.Decode(&n); err != nil {
		if cerr := w.ctx.Err(); cerr != nil {
			err = cerr
		}
		return ipn.Notify{}, err
	}
	return n, nil
}

// SuggestExitNode requests an exit node suggestion and returns the exit node's details.
func (lc *LocalClient) SuggestExitNode(ctx context.Context) (apitype.ExitNodeSuggestionResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/suggest-exit-node")
	if err != nil {
		return apitype.ExitNodeSuggestionResponse{}, err
	}
	return decodeJSON[apitype.ExitNodeSuggestionResponse](body)
}
