// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tsweb contains code used in various Tailscale webservers.
package tsweb

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"expvar"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/logger"
	"tailscale.com/util/cmpx"
	"tailscale.com/util/vizerror"
)

// DevMode controls whether extra output in shown, for when the binary is being run in dev mode.
var DevMode bool

func DefaultCertDir(leafDir string) string {
	cacheDir, err := os.UserCacheDir()
	if err == nil {
		return filepath.Join(cacheDir, "tailscale", leafDir)
	}
	return ""
}

// IsProd443 reports whether addr is a Go listen address for port 443.
func IsProd443(addr string) bool {
	_, port, _ := net.SplitHostPort(addr)
	return port == "443" || port == "https"
}

// AllowDebugAccess reports whether r should be permitted to access
// various debug endpoints.
func AllowDebugAccess(r *http.Request) bool {
	if allowDebugAccessWithKey(r) {
		return true
	}
	if r.Header.Get("X-Forwarded-For") != "" {
		// TODO if/when needed. For now, conservative:
		return false
	}
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if tsaddr.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == envknob.String("TS_ALLOW_DEBUG_IP") {
		return true
	}
	return false
}

func allowDebugAccessWithKey(r *http.Request) bool {
	if r.Method != "GET" {
		return false
	}
	urlKey := r.FormValue("debugkey")
	keyPath := envknob.String("TS_DEBUG_KEY_PATH")
	if urlKey != "" && keyPath != "" {
		slurp, err := os.ReadFile(keyPath)
		if err == nil && string(bytes.TrimSpace(slurp)) == urlKey {
			return true
		}
	}
	return false
}

// AcceptsEncoding reports whether r accepts the named encoding
// ("gzip", "br", etc).
func AcceptsEncoding(r *http.Request, enc string) bool {
	h := r.Header.Get("Accept-Encoding")
	if h == "" {
		return false
	}
	if !strings.Contains(h, enc) && !mem.ContainsFold(mem.S(h), mem.S(enc)) {
		return false
	}
	remain := h
	for len(remain) > 0 {
		var part string
		part, remain, _ = strings.Cut(remain, ",")
		part = strings.TrimSpace(part)
		part, _, _ = strings.Cut(part, ";")
		if part == enc {
			return true
		}
	}
	return false
}

// Protected wraps a provided debug handler, h, returning a Handler
// that enforces AllowDebugAccess and returns forbidden replies for
// unauthorized requests.
func Protected(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !AllowDebugAccess(r) {
			msg := "debug access denied"
			if DevMode {
				ipStr, _, _ := net.SplitHostPort(r.RemoteAddr)
				msg += fmt.Sprintf("; to permit access, set TS_ALLOW_DEBUG_IP=%v", ipStr)
			}
			http.Error(w, msg, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Port80Handler is the handler to be given to
// autocert.Manager.HTTPHandler.  The inner handler is the mux
// returned by NewMux containing registered /debug handlers.
type Port80Handler struct {
	Main http.Handler
	// FQDN is used to redirect incoming requests to https://<FQDN>.
	// If it is not set, the hostname is calculated from the incoming
	// request.
	FQDN string
}

func (h Port80Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.RequestURI
	if path == "/debug" || strings.HasPrefix(path, "/debug") {
		h.Main.ServeHTTP(w, r)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	if path == "/" && AllowDebugAccess(r) {
		// Redirect authorized user to the debug handler.
		path = "/debug/"
	}
	host := cmpx.Or(h.FQDN, r.Host)
	target := "https://" + host + path
	http.Redirect(w, r, target, http.StatusFound)
}

// ReturnHandler is like net/http.Handler, but the handler can return an
// error instead of writing to its ResponseWriter.
type ReturnHandler interface {
	// ServeHTTPReturn is like http.Handler.ServeHTTP, except that
	// it can choose to return an error instead of writing to its
	// http.ResponseWriter.
	//
	// If ServeHTTPReturn returns an error, it caller should handle
	// an error by serving an HTTP 500 response to the user. The
	// error details should not be sent to the client, as they may
	// contain sensitive information. If the error is an
	// HTTPError, though, callers should use the HTTP response
	// code and message as the response to the client.
	ServeHTTPReturn(http.ResponseWriter, *http.Request) error
}

type HandlerOptions struct {
	QuietLoggingIfSuccessful bool // if set, do not log successfully handled HTTP requests (200 and 304 status codes)
	Logf                     logger.Logf
	Now                      func() time.Time // if nil, defaults to time.Now

	// If non-nil, StatusCodeCounters maintains counters
	// of status codes for handled responses.
	// The keys are "1xx", "2xx", "3xx", "4xx", and "5xx".
	StatusCodeCounters *expvar.Map
	// If non-nil, StatusCodeCountersFull maintains counters of status
	// codes for handled responses.
	// The keys are HTTP numeric response codes e.g. 200, 404, ...
	StatusCodeCountersFull *expvar.Map

	// OnError is called if the handler returned a HTTPError. This
	// is intended to be used to present pretty error pages if
	// the user agent is determined to be a browser.
	OnError ErrorHandlerFunc
}

// ErrorHandlerFunc is called to present a error response.
type ErrorHandlerFunc func(http.ResponseWriter, *http.Request, HTTPError)

// ReturnHandlerFunc is an adapter to allow the use of ordinary
// functions as ReturnHandlers. If f is a function with the
// appropriate signature, ReturnHandlerFunc(f) is a ReturnHandler that
// calls f.
type ReturnHandlerFunc func(http.ResponseWriter, *http.Request) error

// A Middleware is a function that wraps an http.Handler to extend or modify
// its behaviour.
//
// The implementation of the wrapper is responsible for delegating its input
// request to the underlying handler, if appropriate.
type Middleware func(h http.Handler) http.Handler

// ServeHTTPReturn calls f(w, r).
func (f ReturnHandlerFunc) ServeHTTPReturn(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// StdHandler converts a ReturnHandler into a standard http.Handler.
// Handled requests are logged using opts.Logf, as are any errors.
// Errors are handled as specified by the Handler interface.
func StdHandler(h ReturnHandler, opts HandlerOptions) http.Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	return retHandler{h, opts}
}

// retHandler is an http.Handler that wraps a Handler and handles errors.
type retHandler struct {
	rh   ReturnHandler
	opts HandlerOptions
}

// ServeHTTP implements the http.Handler interface.
func (h retHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg := AccessLogRecord{
		When:       h.opts.Now(),
		RemoteAddr: r.RemoteAddr,
		Proto:      r.Proto,
		TLS:        r.TLS != nil,
		Host:       r.Host,
		Method:     r.Method,
		RequestURI: r.URL.RequestURI(),
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
		RequestID:  RequestIDFromContext(r.Context()),
	}

	lw := &loggingResponseWriter{ResponseWriter: w, logf: h.opts.Logf}
	err := h.rh.ServeHTTPReturn(lw, r)

	var hErr HTTPError
	var hErrOK bool
	if errors.As(err, &hErr) {
		hErrOK = true
	} else if vizErr, ok := vizerror.As(err); ok {
		hErrOK = true
		hErr = HTTPError{Msg: vizErr.Error()}
	}

	if lw.code == 0 && err == nil && !lw.hijacked {
		// If the handler didn't write and didn't send a header, that still means 200.
		// (See https://play.golang.org/p/4P7nx_Tap7p)
		lw.code = 200
	}

	msg.Seconds = h.opts.Now().Sub(msg.When).Seconds()
	msg.Code = lw.code
	msg.Bytes = lw.bytes

	switch {
	case lw.hijacked:
		// Connection no longer belongs to us, just log that we
		// switched protocols away from HTTP.
		if msg.Code == 0 {
			msg.Code = http.StatusSwitchingProtocols
		}
	case err != nil && r.Context().Err() == context.Canceled:
		msg.Code = 499 // nginx convention: Client Closed Request
		msg.Err = context.Canceled.Error()
	case hErrOK:
		// Handler asked us to send an error. Do so, if we haven't
		// already sent a response.
		msg.Err = hErr.Msg
		if hErr.Err != nil {
			if msg.Err == "" {
				msg.Err = hErr.Err.Error()
			} else {
				msg.Err = msg.Err + ": " + hErr.Err.Error()
			}
		}
		if lw.code != 0 {
			h.opts.Logf("[unexpected] handler returned HTTPError %v, but already sent a response with code %d", hErr, lw.code)
			break
		}
		msg.Code = hErr.Code
		if msg.Code == 0 {
			h.opts.Logf("[unexpected] HTTPError %v did not contain an HTTP status code, sending internal server error", hErr)
			msg.Code = http.StatusInternalServerError
		}
		if h.opts.OnError != nil {
			h.opts.OnError(lw, r, hErr)
		} else {
			// Default headers set by http.Error.
			lw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			lw.Header().Set("X-Content-Type-Options", "nosniff")
			for k, vs := range hErr.Header {
				lw.Header()[k] = vs
			}
			lw.WriteHeader(msg.Code)
			fmt.Fprintln(lw, hErr.Msg)
			if msg.RequestID != "" {
				fmt.Fprintln(lw, msg.RequestID)
			}
		}
	case err != nil:
		const internalServerError = "internal server error"
		errorMessage := internalServerError
		if msg.RequestID != "" {
			errorMessage += "\n" + string(msg.RequestID)
		}
		// Handler returned a generic error. Serve an internal server
		// error, if necessary.
		msg.Err = err.Error()
		if lw.code == 0 {
			msg.Code = http.StatusInternalServerError
			http.Error(lw, errorMessage, msg.Code)
		}
	}

	if !h.opts.QuietLoggingIfSuccessful || (msg.Code != http.StatusOK && msg.Code != http.StatusNotModified) {
		h.opts.Logf("%s", msg)
	}

	if h.opts.StatusCodeCounters != nil {
		h.opts.StatusCodeCounters.Add(responseCodeString(msg.Code/100), 1)
	}

	if h.opts.StatusCodeCountersFull != nil {
		h.opts.StatusCodeCountersFull.Add(responseCodeString(msg.Code), 1)
	}
}

func responseCodeString(code int) string {
	if v, ok := responseCodeCache.Load(code); ok {
		return v.(string)
	}

	var ret string
	if code < 10 {
		ret = fmt.Sprintf("%dxx", code)
	} else {
		ret = strconv.Itoa(code)
	}
	responseCodeCache.Store(code, ret)
	return ret
}

// responseCodeCache memoizes the string form of HTTP response codes,
// so that the hot request-handling codepath doesn't have to allocate
// in strconv/fmt for every request.
//
// Keys are either full HTTP response code ints (200, 404) or "family"
// ints representing entire families (e.g. 2 for 2xx codes). Values
// are the string form of that code/family.
var responseCodeCache sync.Map

// loggingResponseWriter wraps a ResponseWriter and record the HTTP
// response code that gets sent, if any.
type loggingResponseWriter struct {
	http.ResponseWriter
	code     int
	bytes    int
	hijacked bool
	logf     logger.Logf
}

// WriteHeader implements http.Handler.
func (l *loggingResponseWriter) WriteHeader(statusCode int) {
	if l.code != 0 {
		l.logf("[unexpected] HTTP handler set statusCode twice (%d and %d)", l.code, statusCode)
		return
	}
	l.code = statusCode
	l.ResponseWriter.WriteHeader(statusCode)
}

// Write implements http.Handler.
func (l *loggingResponseWriter) Write(bs []byte) (int, error) {
	if l.code == 0 {
		l.code = 200
	}
	n, err := l.ResponseWriter.Write(bs)
	l.bytes += n
	return n, err
}

// Hijack implements http.Hijacker. Note that hijacking can still fail
// because the wrapped ResponseWriter is not required to implement
// Hijacker, as this breaks HTTP/2.
func (l *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := l.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter is not a Hijacker")
	}
	conn, buf, err := h.Hijack()
	if err == nil {
		l.hijacked = true
	}
	return conn, buf, err
}

func (l loggingResponseWriter) Flush() {
	f, _ := l.ResponseWriter.(http.Flusher)
	if f == nil {
		l.logf("[unexpected] tried to Flush a ResponseWriter that can't flush")
		return
	}
	f.Flush()
}

// HTTPError is an error with embedded HTTP response information.
//
// It is the error type to be (optionally) used by Handler.ServeHTTPReturn.
type HTTPError struct {
	Code   int         // HTTP response code to send to client; 0 means 500
	Msg    string      // Response body to send to client
	Err    error       // Detailed error to log on the server
	Header http.Header // Optional set of HTTP headers to set in the response
}

// Error implements the error interface.
func (e HTTPError) Error() string { return fmt.Sprintf("httperror{%d, %q, %v}", e.Code, e.Msg, e.Err) }
func (e HTTPError) Unwrap() error { return e.Err }

// Error returns an HTTPError containing the given information.
func Error(code int, msg string, err error) HTTPError {
	return HTTPError{Code: code, Msg: msg, Err: err}
}

// VarzHandler writes expvar values as Prometheus metrics.
// TODO: migrate all users to varz.Handler or promvarz.Handler and remove this.
func VarzHandler(w http.ResponseWriter, r *http.Request) {
	varz.Handler(w, r)
}

// AddBrowserHeaders sets various HTTP security headers for browser-facing endpoints.
//
// The specific headers:
//   - require HTTPS access (HSTS)
//   - disallow iframe embedding
//   - mitigate MIME confusion attacks
//
// These headers are based on
// https://infosec.mozilla.org/guidelines/web_security
func AddBrowserHeaders(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; block-all-mixed-content; object-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// BrowserHeaderHandler wraps the provided http.Handler with a call to
// AddBrowserHeaders.
func BrowserHeaderHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AddBrowserHeaders(w)
		h.ServeHTTP(w, r)
	})
}

// BrowserHeaderHandlerFunc wraps the provided http.HandlerFunc with a call to
// AddBrowserHeaders.
func BrowserHeaderHandlerFunc(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		AddBrowserHeaders(w)
		h.ServeHTTP(w, r)
	}
}
