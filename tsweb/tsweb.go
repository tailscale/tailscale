// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsweb contains code used in various Tailscale webservers.
package tsweb

import (
	"bytes"
	"context"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

// DevMode controls whether extra output in shown, for when the binary is being run in dev mode.
var DevMode bool

// NewMux returns a new ServeMux with debugHandler registered (and protected) at /debug/.
func NewMux(debugHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	registerCommonDebug(mux)
	mux.Handle("/debug/", Protected(debugHandler))
	return mux
}

func registerCommonDebug(mux *http.ServeMux) {
	expvar.Publish("counter_uptime_sec", expvar.Func(func() interface{} { return int64(Uptime().Seconds()) }))
	mux.Handle("/debug/pprof/", Protected(http.DefaultServeMux)) // to net/http/pprof
	mux.Handle("/debug/vars", Protected(http.DefaultServeMux))   // to expvar
	mux.Handle("/debug/varz", Protected(http.HandlerFunc(varzHandler)))
}

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
	ip := net.ParseIP(ipStr)
	if interfaces.IsTailscaleIP(ip) || ip.IsLoopback() || ipStr == os.Getenv("TS_ALLOW_DEBUG_IP") {
		return true
	}
	if r.Method == "GET" {
		urlKey := r.FormValue("debugkey")
		keyPath := os.Getenv("TS_DEBUG_KEY_PATH")
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
// that enforces AllowDebugAccess and returns forbiden replies for
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

// Handler is like net/http.Handler, but the handler can return an
// error instead of writing to its ResponseWriter.
//
// ServeHTTPErr should behave like http.Handler.ServeHTTP, except that
// it can choose to return an error instead of writing to its
// http.ResponseWriter.
//
// Callers of Handler should handle an error by serving a 500 error to
// the user. The error details should not be sent to the client, as
// they may contain sensitive information.
//
// In addition, if the returned error is an HTTPError, callers should
// use the HTTP response code and message as the response to the
// client.
type Handler interface {
	ServeHTTPErr(http.ResponseWriter, *http.Request) error
}

// handler is an http.Handler that wraps a Handler and handles errors.
type handler struct {
	h    Handler
	logf logger.Logf
}

// ServeHTTP implements the http.Handler interface.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg := Msg{
		Where: "http",
		When:  time.Now(),
		HTTP: &MsgHTTP{
			Path:       r.URL.Path,
			RemoteAddr: r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Referer:    r.Referer(),
		},
	}
	err := h.h.ServeHTTPErr(w, r)
	if err == context.Canceled {
		// No need to inform client, but still log the
		// cancellation.
		msg.HTTP.Code = 499 // nginx convention: Client Closed Request
		msg.Err = err
	} else if hErr, ok := err.(HTTPError); ok {
		msg.HTTP.Code = hErr.Code
		msg.Err = hErr.Err
		msg.Msg = hErr.Msg
		http.Error(w, hErr.Msg, hErr.Code)
	} else if err != nil {
		msg.HTTP.Code = 500
		msg.Err = err
		msg.Msg = "internal server error"
		http.Error(w, msg.Msg, msg.HTTP.Code)
	}

	// TODO(danderson): needed? Copied from existing code, but
	// doesn't HTTPServer do this by itself?
	if f, _ := w.(http.Flusher); f != nil {
		f.Flush()
	}
	h.logf("%s", msg)
}

// StdHandler converts a Handler into a standard http.Handler.
// Handled requests and any errors returned by h are logged using
// logf. Errors are handled as specified by the Handler interface.
func StdHandler(h Handler, logf logger.Logf) http.Handler {
	return handler{h, logf}
}

// HTTPError is an error with embedded HTTP response information.
type HTTPError struct {
	Code int    // HTTP response code to send to client
	Msg  string // Response body to send to client
	Err  error  // Detailed error to log on the server
}

// Error implements the error interface.
func (e HTTPError) Error() string { return fmt.Sprintf("httperror{%d, %q, %v}", e.Code, e.Msg, e.Err) }

// Error returns an HTTPError containing the given information.
func Error(code int, msg string, err error) HTTPError {
	return HTTPError{Code: code, Msg: msg, Err: err}
}

// varzHandler is an HTTP handler to write expvar values into the
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
func varzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	var dump func(prefix string, kv expvar.KeyValue)
	dump = func(prefix string, kv expvar.KeyValue) {
		name := prefix + kv.Key

		var typ string
		switch {
		case strings.HasPrefix(kv.Key, "gauge_"):
			typ = "gauge"
			name = prefix + strings.TrimPrefix(kv.Key, "gauge_")

		case strings.HasPrefix(kv.Key, "counter_"):
			typ = "counter"
			name = prefix + strings.TrimPrefix(kv.Key, "counter_")
		}

		switch v := kv.Value.(type) {
		case *expvar.Int:
			if typ == "" {
				typ = "counter"
			}
			fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, typ, name, v.Value())
			return
		case *metrics.Set:
			v.Do(func(kv expvar.KeyValue) {
				dump(name+"_", kv)
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
				funcRet = fmt.Sprintf(" returning %T", v)
			}
			fmt.Fprintf(w, "# skipping expvar %q (Go type %T%s) with undeclared Prometheus type\n", name, kv.Value, funcRet)
			return
		}

		switch v := kv.Value.(type) {
		case expvar.Func:
			val := v()
			switch val.(type) {
			case int64, int:
				fmt.Fprintf(w, "# TYPE %s %s\n%s %v\n", name, typ, name, val)
			default:
				fmt.Fprintf(w, "# skipping expvar func %q returning unknown type %T\n", name, val)
			}

		case *metrics.LabelMap:
			fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
			// IntMap uses expvar.Map on the inside, which presorts
			// keys. The output ordering is deterministic.
			v.Do(func(kv expvar.KeyValue) {
				fmt.Fprintf(w, "%s{%s=%q} %v\n", name, v.Label, kv.Key, kv.Value)
			})
		}
	}
	expvar.Do(func(kv expvar.KeyValue) {
		dump("", kv)
	})
}

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
