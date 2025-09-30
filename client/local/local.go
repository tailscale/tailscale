// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package local contains a Go client for the Tailscale LocalAPI.
package local

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
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

	"tailscale.com/appc"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/drive"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netutil"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus"
)

// defaultClient is the default Client when using the legacy
// package-level functions.
var defaultClient Client

// Client is a client to Tailscale's "LocalAPI", communicating with the
// Tailscale daemon on the local machine. Its API is not necessarily stable and
// subject to changes between releases. Some API calls have stricter
// compatibility guarantees, once they've been widely adopted. See method docs
// for details.
//
// Its zero value is valid to use.
//
// Any exported fields should be set before using methods on the type
// and not changed thereafter.
type Client struct {
	// Dial optionally specifies an alternate func that connects to the local
	// machine's tailscaled or equivalent. If nil, a default is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Transport optionally specifies an alternate [http.RoundTripper]
	// used to execute HTTP requests. If nil, a default [http.Transport] is used,
	// potentially with custom dialing logic from [Dial].
	// It is primarily used for testing.
	Transport http.RoundTripper

	// Socket specifies an alternate path to the local Tailscale socket.
	// If empty, a platform-specific default is used.
	Socket string

	// UseSocketOnly, if true, tries to only connect to tailscaled via the
	// Unix socket and not via fallback mechanisms as done on macOS when
	// connecting to the GUI client variants.
	UseSocketOnly bool

	// OmitAuth, if true, omits sending the local Tailscale daemon any
	// authentication token that might be required by the platform.
	//
	// As of 2024-08-12, only macOS uses an authentication token. OmitAuth is
	// meant for when Dial is set and the LocalAPI is being proxied to a
	// different operating system, such as in integration tests.
	OmitAuth bool

	// tsClient does HTTP requests to the local Tailscale daemon.
	// It's lazily initialized on first use.
	tsClient     *http.Client
	tsClientOnce sync.Once
}

func (lc *Client) socket() string {
	if lc.Socket != "" {
		return lc.Socket
	}
	return paths.DefaultTailscaledSocket()
}

func (lc *Client) dialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if lc.Dial != nil {
		return lc.Dial
	}
	return lc.defaultDialer
}

func (lc *Client) defaultDialer(ctx context.Context, network, addr string) (net.Conn, error) {
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
	return safesocket.ConnectContext(ctx, lc.socket())
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
func (lc *Client) DoLocalRequest(req *http.Request) (*http.Response, error) {
	req.Header.Set("Tailscale-Cap", strconv.Itoa(int(tailcfg.CurrentCapabilityVersion)))
	lc.tsClientOnce.Do(func() {
		lc.tsClient = &http.Client{
			Transport: cmp.Or(lc.Transport, http.RoundTripper(
				&http.Transport{DialContext: lc.dialer()}),
			),
		}
	})
	if !lc.OmitAuth {
		if _, token, err := safesocket.LocalTCPPortAndToken(); err == nil {
			req.SetBasicAuth("", token)
		}
	}
	return lc.tsClient.Do(req)
}

func (lc *Client) doLocalRequestNiceError(req *http.Request) (*http.Response, error) {
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

func (lc *Client) send(ctx context.Context, method, path string, wantStatus int, body io.Reader) ([]byte, error) {
	var headers http.Header
	if reason := apitype.RequestReasonKey.Value(ctx); reason != "" {
		reasonBase64 := base64.StdEncoding.EncodeToString([]byte(reason))
		headers = http.Header{apitype.RequestReasonHeader: {reasonBase64}}
	}
	slurp, _, err := lc.sendWithHeaders(ctx, method, path, wantStatus, body, headers)
	return slurp, err
}

func (lc *Client) sendWithHeaders(
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
		return nil, nil, httpStatusError{bestError(err, slurp), res.StatusCode}
	}
	return slurp, res.Header, nil
}

type httpStatusError struct {
	error
	HTTPStatus int
}

func (lc *Client) get200(ctx context.Context, path string) ([]byte, error) {
	return lc.send(ctx, "GET", path, 200, nil)
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
//
// Deprecated: use [Client.WhoIs].
func WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return defaultClient.WhoIs(ctx, remoteAddr)
}

func decodeJSON[T any](b []byte) (ret T, err error) {
	if err := json.Unmarshal(b, &ret); err != nil {
		var zero T
		return zero, fmt.Errorf("failed to unmarshal JSON into %T: %w", ret, err)
	}
	return ret, nil
}

// WhoIs returns the owner of the remoteAddr, which must be an IP or IP:port.
//
// If not found, the error is [ErrPeerNotFound].
//
// For connections proxied by tailscaled, this looks up the owner of the given
// address as TCP first, falling back to UDP; if you want to only check a
// specific address family, use WhoIsProto.
func (lc *Client) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(remoteAddr))
	if err != nil {
		if hs, ok := err.(httpStatusError); ok && hs.HTTPStatus == http.StatusNotFound {
			return nil, ErrPeerNotFound
		}
		return nil, err
	}
	return decodeJSON[*apitype.WhoIsResponse](body)
}

// ErrPeerNotFound is returned by [Client.WhoIs], [Client.WhoIsNodeKey] and
// [Client.WhoIsProto] when a peer is not found.
var ErrPeerNotFound = errors.New("peer not found")

// WhoIsNodeKey returns the owner of the given wireguard public key.
//
// If not found, the error is ErrPeerNotFound.
func (lc *Client) WhoIsNodeKey(ctx context.Context, key key.NodePublic) (*apitype.WhoIsResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/whois?addr="+url.QueryEscape(key.String()))
	if err != nil {
		if hs, ok := err.(httpStatusError); ok && hs.HTTPStatus == http.StatusNotFound {
			return nil, ErrPeerNotFound
		}
		return nil, err
	}
	return decodeJSON[*apitype.WhoIsResponse](body)
}

// WhoIsProto returns the owner of the remoteAddr, which must be an IP or
// IP:port, for the given protocol (tcp or udp).
//
// If not found, the error is [ErrPeerNotFound].
func (lc *Client) WhoIsProto(ctx context.Context, proto, remoteAddr string) (*apitype.WhoIsResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/whois?proto="+url.QueryEscape(proto)+"&addr="+url.QueryEscape(remoteAddr))
	if err != nil {
		if hs, ok := err.(httpStatusError); ok && hs.HTTPStatus == http.StatusNotFound {
			return nil, ErrPeerNotFound
		}
		return nil, err
	}
	return decodeJSON[*apitype.WhoIsResponse](body)
}

// Goroutines returns a dump of the Tailscale daemon's current goroutines.
func (lc *Client) Goroutines(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/goroutines")
}

// DaemonMetrics returns the Tailscale daemon's metrics in
// the Prometheus text exposition format.
func (lc *Client) DaemonMetrics(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/metrics")
}

// UserMetrics returns the user metrics in
// the Prometheus text exposition format.
func (lc *Client) UserMetrics(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/usermetrics")
}

// IncrementCounter increments the value of a Tailscale daemon's counter
// metric by the given delta. If the metric has yet to exist, a new counter
// metric is created and initialized to delta.
//
// IncrementCounter does not support gauge metrics or negative delta values.
func (lc *Client) IncrementCounter(ctx context.Context, name string, delta int) error {
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

// IncrementGauge increments the value of a Tailscale daemon's gauge
// metric by the given delta. If the metric has yet to exist, a new gauge
// metric is created and initialized to delta. The delta value can be negative.
func (lc *Client) IncrementGauge(ctx context.Context, name string, delta int) error {
	type metricUpdate struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value int    `json:"value"` // amount to increment by
	}
	_, err := lc.send(ctx, "POST", "/localapi/v0/upload-client-metrics", 200, jsonBody([]metricUpdate{{
		Name:  name,
		Type:  "gauge",
		Value: delta,
	}}))
	return err
}

// TailDaemonLogs returns a stream the Tailscale daemon's logs as they arrive.
// Close the context to stop the stream.
func (lc *Client) TailDaemonLogs(ctx context.Context) (io.Reader, error) {
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

// EventBusGraph returns a graph of active publishers and subscribers in the eventbus
// as a [eventbus.DebugTopics]
func (lc *Client) EventBusGraph(ctx context.Context) ([]byte, error) {
	return lc.get200(ctx, "/localapi/v0/debug-bus-graph")
}

// StreamBusEvents returns an iterator of Tailscale bus events as they arrive.
// Each pair is a valid event and a nil error, or a zero event a non-nil error.
// In case of error, the iterator ends after the pair reporting the error.
// Iteration stops if ctx ends.
func (lc *Client) StreamBusEvents(ctx context.Context) iter.Seq2[eventbus.DebugEvent, error] {
	return func(yield func(eventbus.DebugEvent, error) bool) {
		req, err := http.NewRequestWithContext(ctx, "GET",
			"http://"+apitype.LocalAPIHost+"/localapi/v0/debug-bus-events", nil)
		if err != nil {
			yield(eventbus.DebugEvent{}, err)
			return
		}
		res, err := lc.doLocalRequestNiceError(req)
		if err != nil {
			yield(eventbus.DebugEvent{}, err)
			return
		}
		if res.StatusCode != http.StatusOK {
			yield(eventbus.DebugEvent{}, errors.New(res.Status))
			return
		}
		defer res.Body.Close()
		dec := json.NewDecoder(bufio.NewReader(res.Body))
		for {
			var evt eventbus.DebugEvent
			if err := dec.Decode(&evt); err == io.EOF {
				return
			} else if err != nil {
				yield(eventbus.DebugEvent{}, err)
				return
			}
			if !yield(evt, nil) {
				return
			}
		}
	}
}

// Pprof returns a pprof profile of the Tailscale daemon.
func (lc *Client) Pprof(ctx context.Context, pprofType string, sec int) ([]byte, error) {
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
func (lc *Client) BugReportWithOpts(ctx context.Context, opts BugReportOpts) (string, error) {
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
// This is the same as calling [Client.BugReportWithOpts] and only specifying the Note
// field.
func (lc *Client) BugReport(ctx context.Context, note string) (string, error) {
	return lc.BugReportWithOpts(ctx, BugReportOpts{Note: note})
}

// DebugAction invokes a debug action, such as "rebind" or "restun".
// These are development tools and subject to change or removal over time.
func (lc *Client) DebugAction(ctx context.Context, action string) error {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug?action="+url.QueryEscape(action), 200, nil)
	if err != nil {
		return fmt.Errorf("error %w: %s", err, body)
	}
	return nil
}

// DebugActionBody invokes a debug action with a body parameter, such as
// "debug-force-prefer-derp".
// These are development tools and subject to change or removal over time.
func (lc *Client) DebugActionBody(ctx context.Context, action string, rbody io.Reader) error {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug?action="+url.QueryEscape(action), 200, rbody)
	if err != nil {
		return fmt.Errorf("error %w: %s", err, body)
	}
	return nil
}

// DebugResultJSON invokes a debug action and returns its result as something JSON-able.
// These are development tools and subject to change or removal over time.
func (lc *Client) DebugResultJSON(ctx context.Context, action string) (any, error) {
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

// SetDevStoreKeyValue set a statestore key/value. It's only meant for development.
// The schema (including when keys are re-read) is not a stable interface.
func (lc *Client) SetDevStoreKeyValue(ctx context.Context, key, value string) error {
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
func (lc *Client) SetComponentDebugLogging(ctx context.Context, component string, d time.Duration) error {
	if !buildfeatures.HasDebug {
		return feature.ErrUnavailable
	}
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
	return defaultClient.Status(ctx)
}

// Status returns the Tailscale daemon's status.
func (lc *Client) Status(ctx context.Context) (*ipnstate.Status, error) {
	return lc.status(ctx, "")
}

// StatusWithoutPeers returns the Tailscale daemon's status, without the peer info.
func StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return defaultClient.StatusWithoutPeers(ctx)
}

// StatusWithoutPeers returns the Tailscale daemon's status, without the peer info.
func (lc *Client) StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return lc.status(ctx, "?peers=false")
}

func (lc *Client) status(ctx context.Context, queryString string) (*ipnstate.Status, error) {
	body, err := lc.get200(ctx, "/localapi/v0/status"+queryString)
	if err != nil {
		return nil, err
	}
	return decodeJSON[*ipnstate.Status](body)
}

// IDToken is a request to get an OIDC ID token for an audience.
// The token can be presented to any resource provider which offers OIDC
// Federation.
func (lc *Client) IDToken(ctx context.Context, aud string) (*tailcfg.TokenResponse, error) {
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
func (lc *Client) WaitingFiles(ctx context.Context) ([]apitype.WaitingFile, error) {
	return lc.AwaitWaitingFiles(ctx, 0)
}

// AwaitWaitingFiles is like [Client.WaitingFiles] but takes a duration to await for an answer.
// If the duration is 0, it will return immediately. The duration is respected at second
// granularity only. If no files are available, it returns (nil, nil).
func (lc *Client) AwaitWaitingFiles(ctx context.Context, d time.Duration) ([]apitype.WaitingFile, error) {
	path := "/localapi/v0/files/?waitsec=" + fmt.Sprint(int(d.Seconds()))
	body, err := lc.get200(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodeJSON[[]apitype.WaitingFile](body)
}

func (lc *Client) DeleteWaitingFile(ctx context.Context, baseName string) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/files/"+url.PathEscape(baseName), http.StatusNoContent, nil)
	return err
}

func (lc *Client) GetWaitingFile(ctx context.Context, baseName string) (rc io.ReadCloser, size int64, err error) {
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

func (lc *Client) FileTargets(ctx context.Context) ([]apitype.FileTarget, error) {
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
func (lc *Client) PushFile(ctx context.Context, target tailcfg.StableNodeID, size int64, name string, r io.Reader) error {
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
func (lc *Client) CheckIPForwarding(ctx context.Context) error {
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
func (lc *Client) CheckUDPGROForwarding(ctx context.Context) error {
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

// CheckReversePathFiltering asks the local Tailscale daemon whether strict
// reverse path filtering is enabled, which would break exit node usage on Linux.
func (lc *Client) CheckReversePathFiltering(ctx context.Context) error {
	body, err := lc.get200(ctx, "/localapi/v0/check-reverse-path-filtering")
	if err != nil {
		return err
	}
	var jres struct {
		Warning string
	}
	if err := json.Unmarshal(body, &jres); err != nil {
		return fmt.Errorf("invalid JSON from check-reverse-path-filtering: %w", err)
	}
	if jres.Warning != "" {
		return errors.New(jres.Warning)
	}
	return nil
}

// SetUDPGROForwarding enables UDP GRO forwarding for the main interface of this
// node. This can be done to improve performance of tailnet nodes acting as exit
// nodes or subnet routers.
// See https://tailscale.com/kb/1320/performance-best-practices#linux-optimizations-for-subnet-routers-and-exit-nodes
func (lc *Client) SetUDPGROForwarding(ctx context.Context) error {
	body, err := lc.get200(ctx, "/localapi/v0/set-udp-gro-forwarding")
	if err != nil {
		return err
	}
	var jres struct {
		Warning string
	}
	if err := json.Unmarshal(body, &jres); err != nil {
		return fmt.Errorf("invalid JSON from set-udp-gro-forwarding: %w", err)
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
func (lc *Client) CheckPrefs(ctx context.Context, p *ipn.Prefs) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/check-prefs", http.StatusOK, jsonBody(p))
	return err
}

func (lc *Client) GetPrefs(ctx context.Context) (*ipn.Prefs, error) {
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

// EditPrefs updates the [ipn.Prefs] of the current Tailscale profile, applying the changes in mp.
// It returns an error if the changes cannot be applied, such as due to the caller's access rights
// or a policy restriction. An optional reason or justification for the request can be
// provided as a context value using [apitype.RequestReasonKey]. If permitted by policy,
// access may be granted, and the reason will be logged for auditing purposes.
func (lc *Client) EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	body, err := lc.send(ctx, "PATCH", "/localapi/v0/prefs", http.StatusOK, jsonBody(mp))
	if err != nil {
		return nil, err
	}
	return decodeJSON[*ipn.Prefs](body)
}

// GetDNSOSConfig returns the system DNS configuration for the current device.
// That is, it returns the DNS configuration that the system would use if Tailscale weren't being used.
func (lc *Client) GetDNSOSConfig(ctx context.Context) (*apitype.DNSOSConfig, error) {
	if !buildfeatures.HasDNS {
		return nil, feature.ErrUnavailable
	}
	body, err := lc.get200(ctx, "/localapi/v0/dns-osconfig")
	if err != nil {
		return nil, err
	}
	var osCfg apitype.DNSOSConfig
	if err := json.Unmarshal(body, &osCfg); err != nil {
		return nil, fmt.Errorf("invalid dns.OSConfig: %w", err)
	}
	return &osCfg, nil
}

// QueryDNS executes a DNS query for a name (`google.com.`) and query type (`CNAME`).
// It returns the raw DNS response bytes and the resolvers that were used to answer the query
// (often just one, but can be more if we raced multiple resolvers).
func (lc *Client) QueryDNS(ctx context.Context, name string, queryType string) (bytes []byte, resolvers []*dnstype.Resolver, err error) {
	if !buildfeatures.HasDNS {
		return nil, nil, feature.ErrUnavailable
	}
	body, err := lc.get200(ctx, fmt.Sprintf("/localapi/v0/dns-query?name=%s&type=%s", url.QueryEscape(name), queryType))
	if err != nil {
		return nil, nil, err
	}
	var res apitype.DNSQueryResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, nil, fmt.Errorf("invalid query response: %w", err)
	}
	return res.Bytes, res.Resolvers, nil
}

// StartLoginInteractive starts an interactive login.
func (lc *Client) StartLoginInteractive(ctx context.Context) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/login-interactive", http.StatusNoContent, nil)
	return err
}

// Start applies the configuration specified in opts, and starts the
// state machine.
func (lc *Client) Start(ctx context.Context, opts ipn.Options) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/start", http.StatusNoContent, jsonBody(opts))
	return err
}

// Logout logs out the current node.
func (lc *Client) Logout(ctx context.Context) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/logout", http.StatusNoContent, nil)
	return err
}

// DialTCP connects to the host's port via Tailscale.
//
// The host may be a base DNS name (resolved from the netmap inside
// tailscaled), a FQDN, or an IP address.
//
// The ctx is only used for the duration of the call, not the lifetime of the [net.Conn].
func (lc *Client) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return lc.UserDial(ctx, "tcp", host, port)
}

// UserDial connects to the host's port via Tailscale for the given network.
//
// The host may be a base DNS name (resolved from the netmap inside tailscaled),
// a FQDN, or an IP address.
//
// The ctx is only used for the duration of the call, not the lifetime of the
// [net.Conn].
func (lc *Client) UserDial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
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
		"Upgrade":      []string{"ts-dial"},
		"Connection":   []string{"upgrade"},
		"Dial-Host":    []string{host},
		"Dial-Port":    []string{fmt.Sprint(port)},
		"Dial-Network": []string{network},
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
func (lc *Client) CurrentDERPMap(ctx context.Context) (*tailcfg.DERPMap, error) {
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
func (lc *Client) PingWithOpts(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType, opts PingOpts) (*ipnstate.PingResult, error) {
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
func (lc *Client) Ping(ctx context.Context, ip netip.Addr, pingtype tailcfg.PingType) (*ipnstate.PingResult, error) {
	return lc.PingWithOpts(ctx, ip, pingtype, PingOpts{})
}

// DisconnectControl shuts down all connections to control, thus making control consider this node inactive. This can be
// run on HA subnet router or app connector replicas before shutting them down to ensure peers get told to switch over
// to another replica whilst there is still some grace period for the existing connections to terminate.
func (lc *Client) DisconnectControl(ctx context.Context) error {
	_, _, err := lc.sendWithHeaders(ctx, "POST", "/localapi/v0/disconnect-control", 200, nil, nil)
	if err != nil {
		return fmt.Errorf("error disconnecting control: %w", err)
	}
	return nil
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
func (lc *Client) ProfileStatus(ctx context.Context) (current ipn.LoginProfile, all []ipn.LoginProfile, err error) {
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
func (lc *Client) ReloadConfig(ctx context.Context) (ok bool, err error) {
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
func (lc *Client) SwitchToEmptyProfile(ctx context.Context) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/profiles/", http.StatusCreated, nil)
	return err
}

// SwitchProfile switches to the given profile.
func (lc *Client) SwitchProfile(ctx context.Context, profile ipn.ProfileID) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/profiles/"+url.PathEscape(string(profile)), 204, nil)
	return err
}

// DeleteProfile removes the profile with the given ID.
// If the profile is the current profile, an empty profile
// will be selected as if [Client.SwitchToEmptyProfile] was called.
func (lc *Client) DeleteProfile(ctx context.Context, profile ipn.ProfileID) error {
	_, err := lc.send(ctx, "DELETE", "/localapi/v0/profiles/"+url.PathEscape(string(profile)), http.StatusNoContent, nil)
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
func (lc *Client) QueryFeature(ctx context.Context, feature string) (*tailcfg.QueryFeatureResponse, error) {
	v := url.Values{"feature": {feature}}
	body, err := lc.send(ctx, "POST", "/localapi/v0/query-feature?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*tailcfg.QueryFeatureResponse](body)
}

func (lc *Client) DebugDERPRegion(ctx context.Context, regionIDOrCode string) (*ipnstate.DebugDERPRegionReport, error) {
	v := url.Values{"region": {regionIDOrCode}}
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug-derp-region?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*ipnstate.DebugDERPRegionReport](body)
}

// DebugPacketFilterRules returns the packet filter rules for the current device.
func (lc *Client) DebugPacketFilterRules(ctx context.Context) ([]tailcfg.FilterRule, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/debug-packet-filter-rules", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[[]tailcfg.FilterRule](body)
}

// DebugSetExpireIn marks the current node key to expire in d.
//
// This is meant primarily for debug and testing.
func (lc *Client) DebugSetExpireIn(ctx context.Context, d time.Duration) error {
	v := url.Values{"expiry": {fmt.Sprint(time.Now().Add(d).Unix())}}
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-expiry-sooner?"+v.Encode(), 200, nil)
	return err
}

// DebugPeerRelaySessions returns debug information about the current peer
// relay sessions running through this node.
func (lc *Client) DebugPeerRelaySessions(ctx context.Context) (*status.ServerStatus, error) {
	body, err := lc.send(ctx, "GET", "/localapi/v0/debug-peer-relay-sessions", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*status.ServerStatus](body)
}

// StreamDebugCapture streams a pcap-formatted packet capture.
//
// The provided context does not determine the lifetime of the
// returned [io.ReadCloser].
func (lc *Client) StreamDebugCapture(ctx context.Context) (io.ReadCloser, error) {
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
// The returned [IPNBusWatcher]'s Close method must be called when done to release
// resources.
//
// A default set of ipn.Notify messages are returned but the set can be modified by mask.
func (lc *Client) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*IPNBusWatcher, error) {
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

// CheckUpdate returns a [*tailcfg.ClientVersion] indicating whether or not an update is available
// to be installed via the LocalAPI. In case the LocalAPI can't install updates, it returns a
// ClientVersion that says that we are up to date.
func (lc *Client) CheckUpdate(ctx context.Context) (*tailcfg.ClientVersion, error) {
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
func (lc *Client) SetUseExitNode(ctx context.Context, on bool) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/set-use-exit-node-enabled?enabled="+strconv.FormatBool(on), http.StatusOK, nil)
	return err
}

// DriveSetServerAddr instructs Taildrive to use the server at addr to access
// the filesystem. This is used on platforms like Windows and MacOS to let
// Taildrive know to use the file server running in the GUI app.
func (lc *Client) DriveSetServerAddr(ctx context.Context, addr string) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/drive/fileserver-address", http.StatusCreated, strings.NewReader(addr))
	return err
}

// DriveShareSet adds or updates the given share in the list of shares that
// Taildrive will serve to remote nodes. If a share with the same name already
// exists, the existing share is replaced/updated.
func (lc *Client) DriveShareSet(ctx context.Context, share *drive.Share) error {
	_, err := lc.send(ctx, "PUT", "/localapi/v0/drive/shares", http.StatusCreated, jsonBody(share))
	return err
}

// DriveShareRemove removes the share with the given name from the list of
// shares that Taildrive will serve to remote nodes.
func (lc *Client) DriveShareRemove(ctx context.Context, name string) error {
	_, err := lc.send(
		ctx,
		"DELETE",
		"/localapi/v0/drive/shares",
		http.StatusNoContent,
		strings.NewReader(name))
	return err
}

// DriveShareRename renames the share from old to new name.
func (lc *Client) DriveShareRename(ctx context.Context, oldName, newName string) error {
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
func (lc *Client) DriveShareList(ctx context.Context) ([]*drive.Share, error) {
	result, err := lc.get200(ctx, "/localapi/v0/drive/shares")
	if err != nil {
		return nil, err
	}
	var shares []*drive.Share
	err = json.Unmarshal(result, &shares)
	return shares, err
}

// IPNBusWatcher is an active subscription (watch) of the local tailscaled IPN bus.
// It's returned by [Client.WatchIPNBus].
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
// If the context from Client.WatchIPNBus is done, that error is returned.
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
func (lc *Client) SuggestExitNode(ctx context.Context) (apitype.ExitNodeSuggestionResponse, error) {
	body, err := lc.get200(ctx, "/localapi/v0/suggest-exit-node")
	if err != nil {
		return apitype.ExitNodeSuggestionResponse{}, err
	}
	return decodeJSON[apitype.ExitNodeSuggestionResponse](body)
}

// ShutdownTailscaled requests a graceful shutdown of tailscaled.
func (lc *Client) ShutdownTailscaled(ctx context.Context) error {
	_, err := lc.send(ctx, "POST", "/localapi/v0/shutdown", 200, nil)
	return err
}

func (lc *Client) GetAppConnectorRouteInfo(ctx context.Context) (appc.RouteInfo, error) {
	body, err := lc.get200(ctx, "/localapi/v0/appc-route-info")
	if err != nil {
		return appc.RouteInfo{}, err
	}
	return decodeJSON[appc.RouteInfo](body)
}
