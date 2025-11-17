// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tsweb contains code used in various Tailscale webservers.
package tsweb

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/metrics"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/logger"
	"tailscale.com/util/ctxkey"
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
	host := cmp.Or(h.FQDN, r.Host)
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

// BucketedStatsOptions describes tsweb handler options surrounding
// the generation of metrics, grouped into buckets.
type BucketedStatsOptions struct {
	// Bucket returns which bucket the given request is in.
	// If nil, [NormalizedPath] is used to compute the bucket.
	Bucket func(req *http.Request) string

	// If non-nil, Started maintains a counter of all requests which
	// have begun processing.
	Started *metrics.LabelMap

	// If non-nil, Finished maintains a counter of all requests which
	// have finished processing with success (that is, the HTTP handler has
	// returned).
	Finished *metrics.LabelMap
}

// normalizePathRegex matches components in a HTTP request path
// that should be replaced.
//
// See: https://regex101.com/r/WIfpaR/3 for the explainer and test cases.
var normalizePathRegex = regexp.MustCompile("([a-fA-F0-9]{9,}|([^\\/])+\\.([^\\/]){2,}|((n|k|u|L|t|S)[a-zA-Z0-9]{5,}(CNTRL|Djz1H|LV5CY|mxgaY|jNy1b))|(([^\\/])+\\@passkey))")

// NormalizedPath returns the given path with the following modifications:
//
//   - any query parameters are removed
//   - any path component with a hex string of 9 or more characters is
//     replaced by an ellipsis
//   - any path component containing a period with at least two characters
//     after the period (i.e. an email or domain)
//   - any path component consisting of a common Tailscale Stable ID
//   - any path segment *@passkey.
func NormalizedPath(p string) string {
	// Fastpath: No hex sequences in there we might have to trim.
	// Avoids allocating.
	if normalizePathRegex.FindStringIndex(p) == nil {
		b, _, _ := strings.Cut(p, "?")
		return b
	}

	// If we got here, there's at least one hex sequences we need to
	// replace with an ellipsis.
	replaced := normalizePathRegex.ReplaceAllString(p, "…")
	b, _, _ := strings.Cut(replaced, "?")
	return b
}

func (o *BucketedStatsOptions) bucketForRequest(r *http.Request) string {
	if o.Bucket != nil {
		return o.Bucket(r)
	}

	return NormalizedPath(r.URL.Path)
}

// HandlerOptions are options used by [StdHandler], containing both [LogOptions]
// used by [LogHandler] and [ErrorOptions] used by [ErrorHandler].
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

	// If non-nil, BucketedStats computes and exposes statistics
	// for each bucket based on the contained parameters.
	BucketedStats *BucketedStatsOptions

	// OnStart is called inline before ServeHTTP is called. Optional.
	OnStart OnStartFunc

	// OnError is called if the handler returned a HTTPError. This
	// is intended to be used to present pretty error pages if
	// the user agent is determined to be a browser.
	OnError ErrorHandlerFunc

	// OnCompletion is called inline when ServeHTTP is finished and gets
	// useful data that the implementor can use for metrics. Optional.
	OnCompletion OnCompletionFunc
}

// LogOptions are the options used by [LogHandler].
// These options are a subset of [HandlerOptions].
type LogOptions struct {
	// Logf is used to log HTTP requests and responses.
	Logf logger.Logf
	// Now is a function giving the current time. Defaults to [time.Now].
	Now func() time.Time

	// QuietLogging suppresses all logging of handled HTTP requests, even if
	// there are errors or status codes considered unsuccessful. Use this option
	// to add your own logging in OnCompletion.
	QuietLogging bool
	// QuietLoggingIfSuccessful suppresses logging of handled HTTP requests
	// where the request's response status code is 200 or 304.
	QuietLoggingIfSuccessful bool

	// StatusCodeCounters maintains counters of status code classes.
	// The keys are "1xx", "2xx", "3xx", "4xx", and "5xx".
	// If nil, no counting is done.
	StatusCodeCounters *expvar.Map
	// StatusCodeCountersFull maintains counters of status codes.
	// The keys are HTTP numeric response codes e.g. 200, 404, ...
	// If nil, no counting is done.
	StatusCodeCountersFull *expvar.Map
	// BucketedStats computes and exposes statistics for each bucket based on
	// the contained parameters. If nil, no counting is done.
	BucketedStats *BucketedStatsOptions

	// OnStart is called inline before ServeHTTP is called. Optional.
	OnStart OnStartFunc
	// OnCompletion is called inline when ServeHTTP is finished and gets
	// useful data that the implementor can use for metrics. Optional.
	OnCompletion OnCompletionFunc
}

func (o HandlerOptions) logOptions() LogOptions {
	return LogOptions{
		QuietLoggingIfSuccessful: o.QuietLoggingIfSuccessful,
		Logf:                     o.Logf,
		Now:                      o.Now,
		StatusCodeCounters:       o.StatusCodeCounters,
		StatusCodeCountersFull:   o.StatusCodeCountersFull,
		BucketedStats:            o.BucketedStats,
		OnStart:                  o.OnStart,
		OnCompletion:             o.OnCompletion,
	}
}

func (opts LogOptions) withDefaults() LogOptions {
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

// ErrorOptions are options used by [ErrorHandler].
type ErrorOptions struct {
	// Logf is used to record unexpected behaviours when returning HTTPError but
	// different error codes have already been written to the client.
	Logf logger.Logf
	// OnError is called if the handler returned a HTTPError. This
	// is intended to be used to present pretty error pages if
	// the user agent is determined to be a browser.
	OnError ErrorHandlerFunc
}

func (opts ErrorOptions) withDefaults() ErrorOptions {
	if opts.Logf == nil {
		opts.Logf = logger.Discard
	}
	if opts.OnError == nil {
		opts.OnError = WriteHTTPError
	}
	return opts
}

func (opts HandlerOptions) errorOptions() ErrorOptions {
	return ErrorOptions{
		OnError: opts.OnError,
	}
}

// ErrorHandlerFunc is called to present a error response.
type ErrorHandlerFunc func(http.ResponseWriter, *http.Request, HTTPError)

// OnStartFunc is called before ServeHTTP is called.
type OnStartFunc func(*http.Request, AccessLogRecord)

// OnCompletionFunc is called when ServeHTTP is finished and gets
// useful data that the implementor can use for metrics.
type OnCompletionFunc func(*http.Request, AccessLogRecord)

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

// MiddlewareStack combines multiple middleware into a single middleware for
// decorating a [http.Handler]. The first middleware argument will be the first
// to process an incoming request, before passing the request onto subsequent
// middleware and eventually the wrapped handler.
//
// For example:
//
//	MiddlewareStack(A, B)(h).ServeHTTP(w, r)
//
// calls in sequence:
//
//	   a.ServeHTTP(w, r)
//	-> b.ServeHTTP(w, r)
//	-> h.ServeHTTP(w, r)
//
// (where the lowercase handlers were generated by the uppercase middleware).
func MiddlewareStack(mw ...Middleware) Middleware {
	if len(mw) == 1 {
		return mw[0]
	}
	return func(h http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			h = mw[i](h)
		}
		return h
	}
}

// ServeHTTPReturn calls f(w, r).
func (f ReturnHandlerFunc) ServeHTTPReturn(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// StdHandler converts a ReturnHandler into a standard http.Handler.
// Handled requests are logged using opts.Logf, as are any errors.
// Errors are handled as specified by the ReturnHandler interface.
// Short-hand for LogHandler(ErrorHandler()).
func StdHandler(h ReturnHandler, opts HandlerOptions) http.Handler {
	return LogHandler(ErrorHandler(h, opts.errorOptions()), opts.logOptions())
}

// LogHandler returns an http.Handler that logs to opts.Logf.
// It logs both successful and failing requests.
// The log line includes the first error returned to [ErrorHandler] within.
// The outer-most LogHandler(LogHandler(...)) does all of the logging.
// Inner LogHandler instance do nothing.
// Panics are swallowed and their stack traces are put in the error.
func LogHandler(h http.Handler, opts LogOptions) http.Handler {
	return logHandler{h, opts.withDefaults()}
}

// ErrorHandler converts a [ReturnHandler] into a standard [http.Handler].
// Errors are handled as specified by the [ReturnHandler.ServeHTTPReturn] method.
// When wrapped in a [LogHandler], panics are added to the [AccessLogRecord];
// otherwise, panics continue up the stack.
func ErrorHandler(h ReturnHandler, opts ErrorOptions) http.Handler {
	return errorHandler{h, opts.withDefaults()}
}

// errCallback is added to logHandler's request context so that errorHandler can
// pass errors back up the stack to logHandler.
var errCallback = ctxkey.New[func(HTTPError)]("tailscale.com/tsweb.errCallback", nil)

// logHandler is a http.Handler which logs the HTTP request.
// It injects an errCallback for errorHandler to augment the log message with
// a specific error.
type logHandler struct {
	h    http.Handler
	opts LogOptions
}

func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If there's already a logHandler up the chain, skip this one.
	ctx := r.Context()
	if errCallback.Has(ctx) {
		h.h.ServeHTTP(w, r)
		return
	}

	msg := AccessLogRecord{
		Time:       h.opts.Now(),
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

	if bs := h.opts.BucketedStats; bs != nil && bs.Started != nil && bs.Finished != nil {
		bucket := bs.bucketForRequest(r)
		var startRecorded bool
		switch v := bs.Started.Map.Get(bucket).(type) {
		case *expvar.Int:
			// If we've already seen this bucket for, count it immediately.
			// Otherwise, for newly seen paths, only count retroactively
			// (so started-finished doesn't go negative) so we don't fill
			// this LabelMap up with internet scanning spam.
			v.Add(1)
			startRecorded = true
		}
		defer func() {
			// Only increment metrics for buckets that result in good HTTP statuses
			// or when we know the start was already counted.
			// Otherwise they get full of internet scanning noise. Only filtering 404
			// gets most of the way there but there are also plenty of URLs that are
			// almost right but result in 400s too. Seem easier to just only ignore
			// all 4xx and 5xx.
			if startRecorded {
				bs.Finished.Add(bucket, 1)
			} else if msg.Code < 400 {
				// This is the first non-error request for this bucket,
				// so count it now retroactively.
				bs.Started.Add(bucket, 1)
				bs.Finished.Add(bucket, 1)
			}
		}()
	}

	if fn := h.opts.OnStart; fn != nil {
		fn(r, msg)
	}

	// Let errorHandler tell us what error it wrote to the client.
	r = r.WithContext(errCallback.WithValue(ctx, func(e HTTPError) {
		// Keep the deepest error.
		if msg.Err != "" {
			return
		}

		// Log the error.
		if e.Msg != "" && e.Err != nil {
			msg.Err = e.Msg + ": " + e.Err.Error()
		} else if e.Err != nil {
			msg.Err = e.Err.Error()
		} else if e.Msg != "" {
			msg.Err = e.Msg
		}

		// We log the code from the loggingResponseWriter, except for
		// cancellation where we override with 499.
		if reqCancelled(r, e.Err) {
			msg.Code = 499
		}
	}))

	lw := newLogResponseWriter(h.opts.Logf, w, r)

	defer func() {
		// If the handler panicked then make sure we include that in our error.
		// Panics caught up errorHandler shouldn't appear here, unless the panic
		// originates in one of its callbacks.
		recovered := recover()
		if recovered != nil {
			if msg.Err == "" {
				msg.Err = panic2err(recovered).Error()
			} else {
				msg.Err += "\n\nthen " + panic2err(recovered).Error()
			}
		}
		h.logRequest(r, lw, msg)
	}()

	h.h.ServeHTTP(lw, r)
}

func (h logHandler) logRequest(r *http.Request, lw *loggingResponseWriter, msg AccessLogRecord) {
	// Complete our access log from the loggingResponseWriter.
	msg.Bytes = lw.bytes
	msg.Seconds = h.opts.Now().Sub(msg.Time).Seconds()
	switch {
	case msg.Code != 0:
		// Keep explicit codes from a few particular errors.
	case lw.hijacked:
		// Connection no longer belongs to us, just log that we
		// switched protocols away from HTTP.
		msg.Code = http.StatusSwitchingProtocols
	case lw.code == 0:
		// If the handler didn't write and didn't send a header, that still means 200.
		// (See https://play.golang.org/p/4P7nx_Tap7p)
		msg.Code = 200
	default:
		msg.Code = lw.code
	}

	// Keep track of the original response code when we've overridden it.
	if lw.code != 0 && msg.Code != lw.code {
		if msg.Err == "" {
			msg.Err = fmt.Sprintf("(original code %d)", lw.code)
		} else {
			msg.Err = fmt.Sprintf("%s (original code %d)", msg.Err, lw.code)
		}
	}

	if !h.opts.QuietLogging && !(h.opts.QuietLoggingIfSuccessful && (msg.Code == http.StatusOK || msg.Code == http.StatusNotModified)) {
		h.opts.Logf("%s", msg)
	}

	if h.opts.OnCompletion != nil {
		h.opts.OnCompletion(r, msg)
	}

	// Closing metrics.
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
	ctx      context.Context
	code     int
	bytes    int
	hijacked bool
	logf     logger.Logf
}

// newLogResponseWriter returns a loggingResponseWriter which uses's the logger
// from r, or falls back to logf. If a nil logger is given, the logs are
// discarded.
func newLogResponseWriter(logf logger.Logf, w http.ResponseWriter, r *http.Request) *loggingResponseWriter {
	if lg, ok := logger.LogfKey.ValueOk(r.Context()); ok && lg != nil {
		logf = lg
	}
	if logf == nil {
		logf = logger.Discard
	}
	return &loggingResponseWriter{
		ResponseWriter: w,
		ctx:            r.Context(),
		logf:           logf,
	}
}

// WriteHeader implements [http.ResponseWriter].
func (lg *loggingResponseWriter) WriteHeader(statusCode int) {
	if lg.code != 0 {
		lg.logf("[unexpected] HTTP handler set statusCode twice (%d and %d)", lg.code, statusCode)
		return
	}
	if lg.ctx.Err() == nil {
		lg.code = statusCode
	}
	lg.ResponseWriter.WriteHeader(statusCode)
}

// Write implements [http.ResponseWriter].
func (lg *loggingResponseWriter) Write(bs []byte) (int, error) {
	if lg.code == 0 {
		lg.code = 200
	}
	n, err := lg.ResponseWriter.Write(bs)
	lg.bytes += n
	return n, err
}

// Hijack implements http.Hijacker. Note that hijacking can still fail
// because the wrapped ResponseWriter is not required to implement
// Hijacker, as this breaks HTTP/2.
func (lg *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := lg.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ResponseWriter is not a Hijacker")
	}
	conn, buf, err := h.Hijack()
	if err == nil {
		lg.hijacked = true
	}
	return conn, buf, err
}

func (lg loggingResponseWriter) Flush() {
	f, _ := lg.ResponseWriter.(http.Flusher)
	if f == nil {
		lg.logf("[unexpected] tried to Flush a ResponseWriter that can't flush")
		return
	}
	f.Flush()
}

// errorHandler is an http.Handler that wraps a ReturnHandler to render the
// returned errors to the client and pass them back to any logHandlers.
type errorHandler struct {
	rh   ReturnHandler
	opts ErrorOptions
}

// ServeHTTP implements the http.Handler interface.
func (h errorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Keep track of whether a response gets written.
	lw, ok := w.(*loggingResponseWriter)
	if !ok {
		lw = newLogResponseWriter(h.opts.Logf, w, r)
	}

	var err error
	defer func() {
		// In case the handler panics, we want to recover and continue logging
		// the error before logging it (or re-panicking if we couldn't log).
		rec := recover()
		if rec != nil {
			err = panic2err(rec)
		}
		if err == nil {
			return
		}
		if h.handleError(w, r, lw, err) {
			return
		}
		if rec != nil {
			// If we weren't able to log the panic somewhere, throw it up the
			// stack to someone who can.
			panic(rec)
		}
	}()
	err = h.rh.ServeHTTPReturn(lw, r)
}

func (h errorHandler) handleError(w http.ResponseWriter, r *http.Request, lw *loggingResponseWriter, err error) bool {
	var logged bool

	// Extract a presentable, loggable error.
	var hOK bool
	var hErr HTTPError
	if errors.As(err, &hErr) {
		hOK = true
		if hErr.Code == 0 {
			lw.logf("[unexpected] HTTPError %v did not contain an HTTP status code, sending internal server error", hErr)
			hErr.Code = http.StatusInternalServerError
		}
	} else if v, ok := vizerror.As(err); ok {
		hErr = Error(http.StatusInternalServerError, v.Error(), nil)
	} else if reqCancelled(r, err) {
		// 499 is the Nginx convention meaning "Client Closed Connection".
		if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrAbortHandler) {
			hErr = Error(499, "", err)
		} else {
			hErr = Error(499, "", fmt.Errorf("%w: %w", context.Canceled, err))
		}
	} else {
		// Omit the friendly message so HTTP logs show the bare error that was
		// returned and we know it's not a HTTPError.
		hErr = Error(http.StatusInternalServerError, "", err)
	}

	// Tell the logger what error we wrote back to the client.
	if pb := errCallback.Value(r.Context()); pb != nil {
		pb(hErr)
		logged = true
	}

	if r.Context().Err() != nil {
		return logged
	}

	if lw.code != 0 {
		if hOK && hErr.Code != lw.code {
			lw.logf("[unexpected] handler returned HTTPError %v, but already sent response with code %d", hErr, lw.code)
		}
		return logged
	}

	// Set a default error message from the status code. Do this after we pass
	// the error back to the logger so that `return errors.New("oh")` logs as
	// `"err": "oh"`, not `"err": "Internal Server Error: oh"`.
	if hErr.Msg == "" {
		switch hErr.Code {
		case 499:
			hErr.Msg = "Client Closed Request"
		default:
			hErr.Msg = http.StatusText(hErr.Code)
		}
	}

	// If OnError panics before a response is written, write a bare 500 back.
	// OnError panics are thrown further up the stack.
	defer func() {
		if lw.code == 0 {
			if rec := recover(); rec != nil {
				w.WriteHeader(http.StatusInternalServerError)
				panic(rec)
			}
		}
	}()

	h.opts.OnError(w, r, hErr)
	return logged
}

// panic2err converts a recovered value to an error containing the panic stack trace.
func panic2err(recovered any) error {
	if recovered == nil {
		return nil
	}
	if recovered == http.ErrAbortHandler {
		return http.ErrAbortHandler
	}

	// Even if r is an error, do not wrap it as an error here as
	// that would allow things like panic(vizerror.New("foo"))
	// which is really hard to define the behavior of.
	var stack [10000]byte
	n := runtime.Stack(stack[:], false)
	return &panicError{
		rec:   recovered,
		stack: stack[:n],
	}
}

// panicError is an error that contains a panic.
type panicError struct {
	rec   any
	stack []byte
}

func (e *panicError) Error() string {
	return fmt.Sprintf("panic: %v\n\n%s", e.rec, e.stack)
}

func (e *panicError) Unwrap() error {
	err, _ := e.rec.(error)
	return err
}

// reqCancelled returns true if err is http.ErrAbortHandler or r.Context.Err()
// is context.Canceled.
func reqCancelled(r *http.Request, err error) bool {
	return errors.Is(err, http.ErrAbortHandler) || r.Context().Err() == context.Canceled
}

// WriteHTTPError is the default error response formatter.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, e HTTPError) {
	// Don't write a response if we've hit a cancellation/abort.
	if r.Context().Err() != nil || errors.Is(e.Err, http.ErrAbortHandler) {
		return
	}

	// Default headers set by http.Error.
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")

	// Custom headers from the error.
	for k, vs := range e.Header {
		h[k] = vs
	}

	// Write the msg back to the user.
	w.WriteHeader(e.Code)
	fmt.Fprint(w, e.Msg)

	// If it's a plaintext message, add line breaks and RequestID.
	if strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		io.WriteString(w, "\n")
		if id := RequestIDFromContext(r.Context()); id != "" {
			io.WriteString(w, id.String())
			io.WriteString(w, "\n")
		}
	}
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

// CleanRedirectURL ensures that urlStr is a valid redirect URL to the
// current server, or one of allowedHosts. Returns the cleaned URL or
// a validation error.
func CleanRedirectURL(urlStr string, allowedHosts []string) (*url.URL, error) {
	if urlStr == "" {
		return &url.URL{}, nil
	}
	// In some places, we unfortunately query-escape the redirect URL
	// too many times, and end up needing to redirect to a URL that's
	// still escaped by one level. Try to unescape the input.
	unescaped, err := url.QueryUnescape(urlStr)
	if err == nil && unescaped != urlStr {
		urlStr = unescaped
	}

	// Go's URL parser and browser URL parsers disagree on the meaning
	// of malformed HTTP URLs. Given the input https:/evil.com, Go
	// parses it as hostname="", path="/evil.com". Browsers parse it
	// as hostname="evil.com", path="". This means that, using
	// malformed URLs, an attacker could trick us into approving of a
	// "local" redirect that in fact sends people elsewhere.
	//
	// This very blunt check enforces that we'll only process
	// redirects that are definitely well-formed URLs.
	//
	// Note that the check for just / also allows URLs of the form
	// "//foo.com/bar", which are scheme-relative redirects. These
	// must be handled with care below when determining whether a
	// redirect is relative to the current host. Notably,
	// url.URL.IsAbs reports // URLs as relative, whereas we want to
	// treat them as absolute redirects and verify the target host.
	if !hasSafeRedirectPrefix(urlStr) {
		return nil, fmt.Errorf("invalid redirect URL %q", urlStr)
	}

	url, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URL %q: %w", urlStr, err)
	}
	// Redirects to self are always allowed. A self redirect must
	// start with url.Path, all prior URL sections must be empty.
	isSelfRedirect := url.Scheme == "" && url.Opaque == "" && url.User == nil && url.Host == ""
	if isSelfRedirect {
		return url, nil
	}
	for _, allowed := range allowedHosts {
		if strings.EqualFold(allowed, url.Hostname()) {
			return url, nil
		}
	}

	return nil, fmt.Errorf("disallowed target host %q in redirect URL %q", url.Hostname(), urlStr)
}

// hasSafeRedirectPrefix reports whether url starts with a slash, or
// one of the case-insensitive strings "http://" or "https://".
func hasSafeRedirectPrefix(url string) bool {
	if len(url) >= 1 && url[0] == '/' {
		return true
	}
	const http = "http://"
	if len(url) >= len(http) && strings.EqualFold(url[:len(http)], http) {
		return true
	}
	const https = "https://"
	if len(url) >= len(https) && strings.EqualFold(url[:len(https)], https) {
		return true
	}
	return false
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
