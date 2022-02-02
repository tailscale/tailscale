// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsweb contains code used in various Tailscale webservers.
package tsweb

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/metrics"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

func init() {
	expvar.Publish("process_start_unix_time", expvar.Func(func() interface{} { return timeStart.Unix() }))
	expvar.Publish("version", expvar.Func(func() interface{} { return version.Long }))
	expvar.Publish("counter_uptime_sec", expvar.Func(func() interface{} { return int64(Uptime().Seconds()) }))
	expvar.Publish("gauge_goroutines", expvar.Func(func() interface{} { return runtime.NumGoroutine() }))
}

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
	if r.Header.Get("X-Forwarded-For") != "" {
		// TODO if/when needed. For now, conservative:
		return false
	}
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		return false
	}
	if tsaddr.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == envknob.String("TS_ALLOW_DEBUG_IP") {
		return true
	}
	if r.Method == "GET" {
		urlKey := r.FormValue("debugkey")
		keyPath := envknob.String("TS_DEBUG_KEY_PATH")
		if urlKey != "" && keyPath != "" {
			slurp, err := ioutil.ReadFile(keyPath)
			if err == nil && string(bytes.TrimSpace(slurp)) == urlKey {
				return true
			}
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

var timeStart = time.Now()

func Uptime() time.Duration { return time.Since(timeStart).Round(time.Second) }

// Port80Handler is the handler to be given to
// autocert.Manager.HTTPHandler.  The inner handler is the mux
// returned by NewMux containing registered /debug handlers.
type Port80Handler struct{ Main http.Handler }

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
	target := "https://" + stripPort(r.Host) + path
	http.Redirect(w, r, target, http.StatusFound)
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return net.JoinHostPort(host, "443")
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
	Quiet200s bool // if set, do not log successfully handled HTTP requests
	Logf      logger.Logf
	Now       func() time.Time // if nil, defaults to time.Now

	// If non-nil, StatusCodeCounters maintains counters
	// of status codes for handled responses.
	// The keys are "1xx", "2xx", "3xx", "4xx", and "5xx".
	StatusCodeCounters *expvar.Map
}

// ReturnHandlerFunc is an adapter to allow the use of ordinary
// functions as ReturnHandlers. If f is a function with the
// appropriate signature, ReturnHandlerFunc(f) is a ReturnHandler that
// calls f.
type ReturnHandlerFunc func(http.ResponseWriter, *http.Request) error

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
	}

	lw := &loggingResponseWriter{ResponseWriter: w, logf: h.opts.Logf}
	err := h.rh.ServeHTTPReturn(lw, r)
	hErr, hErrOK := err.(HTTPError)

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
		http.Error(lw, hErr.Msg, msg.Code)
	case err != nil:
		// Handler returned a generic error. Serve an internal server
		// error, if necessary.
		msg.Err = err.Error()
		if lw.code == 0 {
			msg.Code = http.StatusInternalServerError
			http.Error(lw, "internal server error", msg.Code)
		}
	}

	if msg.Code != 200 || !h.opts.Quiet200s {
		h.opts.Logf("%s", msg)
	}

	if h.opts.StatusCodeCounters != nil {
		key := fmt.Sprintf("%dxx", msg.Code/100)
		h.opts.StatusCodeCounters.Add(key, 1)
	}
}

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

func (l *loggingResponseWriter) httpCode() int {
	switch {
	case l.code != 0:
		return l.code
	case l.hijacked:
		return http.StatusSwitchingProtocols
	case l.ctx.Err() == context.Canceled:
		return 499 // nginx convention: Client Closed Request
	default:
		// Handler didn't write a body or send a header, that means 200.
		return 200
	}
}

// HTTPError is an error with embedded HTTP response information.
//
// It is the error type to be (optionally) used by Handler.ServeHTTPReturn.
type HTTPError struct {
	Code int    // HTTP response code to send to client; 0 means means 500
	Msg  string // Response body to send to client
	Err  error  // Detailed error to log on the server
}

// Error implements the error interface.
func (e HTTPError) Error() string { return fmt.Sprintf("httperror{%d, %q, %v}", e.Code, e.Msg, e.Err) }

// Error returns an HTTPError containing the given information.
func Error(code int, msg string, err error) HTTPError {
	return HTTPError{Code: code, Msg: msg, Err: err}
}

// WritePrometheusExpvar writes kv to w in Prometheus metrics format.
//
// See VarzHandler for conventions. This is exported primarily for
// people to test their varz.
func WritePrometheusExpvar(w io.Writer, kv expvar.KeyValue) {
	writePromExpVar(w, "", kv)
}

func writePromExpVar(w io.Writer, prefix string, kv expvar.KeyValue) {
	key := kv.Key
	var typ string
	var label string
	switch {
	case strings.HasPrefix(kv.Key, "gauge_"):
		typ = "gauge"
		key = strings.TrimPrefix(kv.Key, "gauge_")

	case strings.HasPrefix(kv.Key, "counter_"):
		typ = "counter"
		key = strings.TrimPrefix(kv.Key, "counter_")
	}
	if strings.HasPrefix(key, "labelmap_") {
		key = strings.TrimPrefix(key, "labelmap_")
		if i := strings.Index(key, "_"); i != -1 {
			label, key = key[:i], key[i+1:]
		}
	}
	name := prefix + key

	switch v := kv.Value.(type) {
	case *expvar.Int:
		if typ == "" {
			typ = "counter"
		}
		fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, typ, name, v.Value())
		return
	case *metrics.Set:
		v.Do(func(kv expvar.KeyValue) {
			writePromExpVar(w, name+"_", kv)
		})
		return
	case PrometheusMetricsReflectRooter:
		root := v.PrometheusMetricsReflectRoot()
		rv := reflect.ValueOf(root)
		if rv.Type().Kind() == reflect.Ptr {
			if rv.IsNil() {
				return
			}
			rv = rv.Elem()
		}
		if rv.Type().Kind() != reflect.Struct {
			fmt.Fprintf(w, "# skipping expvar %q; unknown root type\n", name)
			return
		}
		foreachExportedStructField(rv, func(fieldOrJSONName, metricType string, rv reflect.Value) {
			mname := name + "_" + fieldOrJSONName
			switch rv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Int())
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Uint())
			case reflect.Float32, reflect.Float64:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", mname, metricType, mname, rv.Float())
			case reflect.Struct:
				if rv.CanAddr() {
					// Slight optimization, not copying big structs if they're addressable:
					writePromExpVar(w, name+"_", expvar.KeyValue{Key: fieldOrJSONName, Value: expVarPromStructRoot{rv.Addr().Interface()}})
				} else {
					writePromExpVar(w, name+"_", expvar.KeyValue{Key: fieldOrJSONName, Value: expVarPromStructRoot{rv.Interface()}})
				}
			}
			return
		})
		return
	}

	if typ == "" {
		var funcRet string
		if f, ok := kv.Value.(expvar.Func); ok {
			v := f()
			if ms, ok := v.(runtime.MemStats); ok && name == "memstats" {
				writeMemstats(w, &ms)
				return
			}
			switch v := v.(type) {
			case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr, float32, float64:
				fmt.Fprintf(w, "%s %v\n", name, v)
				return
			}
			funcRet = fmt.Sprintf(" returning %T", v)
		}
		switch kv.Value.(type) {
		default:
			fmt.Fprintf(w, "# skipping expvar %q (Go type %T%s) with undeclared Prometheus type\n", name, kv.Value, funcRet)
			return
		case *metrics.LabelMap, *expvar.Map:
			// Permit typeless LabelMap and expvar.Map for
			// compatibility with old expvar-registered
			// metrics.LabelMap.
		}
	}

	switch v := kv.Value.(type) {
	case expvar.Func:
		val := v()
		switch val.(type) {
		case float64, int64, int:
			fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, typ, name, val)
		default:
			fmt.Fprintf(w, "# skipping expvar func %q returning unknown type %T\n", name, val)
		}

	case *metrics.LabelMap:
		if typ != "" {
			fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
		}
		// IntMap uses expvar.Map on the inside, which presorts
		// keys. The output ordering is deterministic.
		v.Do(func(kv expvar.KeyValue) {
			fmt.Fprintf(w, "%s{%s=%q} %v\n", name, v.Label, kv.Key, kv.Value)
		})
	case *expvar.Map:
		if label != "" && typ != "" {
			fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
			v.Do(func(kv expvar.KeyValue) {
				fmt.Fprintf(w, "%s{%s=%q} %v\n", name, label, kv.Key, kv.Value)
			})
		} else {
			v.Do(func(kv expvar.KeyValue) {
				fmt.Fprintf(w, "%s_%s %v\n", name, kv.Key, kv.Value)
			})
		}
	}
}

// VarzHandler is an HTTP handler to write expvar values into the
// prometheus export format:
//
//   https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
//
// It makes the following assumptions:
//
//   * *expvar.Int are counters (unless marked as a gauge_; see below)
//   * a *tailscale/metrics.Set is descended into, joining keys with
//     underscores. So use underscores as your metric names.
//   * an expvar named starting with "gauge_" or "counter_" is of that
//     Prometheus type, and has that prefix stripped.
//   * anything else is untyped and thus not exported.
//   * expvar.Func can return an int or int64 (for now) and anything else
//     is not exported.
//
// This will evolve over time, or perhaps be replaced.
func VarzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	expvarDo(func(kv expvar.KeyValue) {
		writePromExpVar(w, "", kv)
	})
}

// PrometheusMetricsReflectRooter is an optional interface that expvar.Var implementations
// can implement to indicate that they should be walked recursively with reflect to find
// sets of fields to export.
type PrometheusMetricsReflectRooter interface {
	expvar.Var

	// PrometheusMetricsReflectRoot returns the struct or struct pointer to walk.
	PrometheusMetricsReflectRoot() interface{}
}

var expvarDo = expvar.Do // pulled out for tests

func writeMemstats(w io.Writer, ms *runtime.MemStats) {
	out := func(name, typ string, v uint64, help string) {
		if help != "" {
			fmt.Fprintf(w, "# HELP memstats_%s %s\n", name, help)
		}
		fmt.Fprintf(w, "# TYPE memstats_%s %s\nmemstats_%s %v\n", name, typ, name, v)
	}
	g := func(name string, v uint64, help string) { out(name, "gauge", v, help) }
	c := func(name string, v uint64, help string) { out(name, "counter", v, help) }
	g("heap_alloc", ms.HeapAlloc, "current bytes of allocated heap objects (up/down smoothly)")
	c("total_alloc", ms.TotalAlloc, "cumulative bytes allocated for heap objects")
	g("sys", ms.Sys, "total bytes of memory obtained from the OS")
	c("mallocs", ms.Mallocs, "cumulative count of heap objects allocated")
	c("frees", ms.Frees, "cumulative count of heap objects freed")
	c("num_gc", uint64(ms.NumGC), "number of completed GC cycles")
}

func foreachExportedStructField(rv reflect.Value, f func(fieldOrJSONName, metricType string, rv reflect.Value)) {
	t := rv.Type()
	for i, n := 0, t.NumField(); i < n; i++ {
		sf := t.Field(i)
		name := sf.Name
		if v := sf.Tag.Get("json"); v != "" {
			if i := strings.Index(v, ","); i != -1 {
				v = v[:i]
			}
			if v == "-" {
				// Skip it, regardless of its metrictype.
				continue
			}
			if v != "" {
				name = v
			}
		}
		metricType := sf.Tag.Get("metrictype")
		if metricType != "" || sf.Type.Kind() == reflect.Struct {
			f(name, metricType, rv.Field(i))
		} else if sf.Type.Kind() == reflect.Ptr && sf.Type.Elem().Kind() == reflect.Struct {
			fv := rv.Field(i)
			if !fv.IsNil() {
				f(name, metricType, fv.Elem())
			}
		}
	}
}

type expVarPromStructRoot struct{ v interface{} }

func (r expVarPromStructRoot) PrometheusMetricsReflectRoot() interface{} { return r.v }
func (r expVarPromStructRoot) String() string                            { panic("unused") }

var (
	_ PrometheusMetricsReflectRooter = expVarPromStructRoot{}
	_ expvar.Var                     = expVarPromStructRoot{}
)
