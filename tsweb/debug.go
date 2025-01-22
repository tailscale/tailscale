// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsweb

import (
	"expvar"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"runtime"

	"tailscale.com/tsweb/promvarz"
	"tailscale.com/tsweb/varz"
	"tailscale.com/version"
)

// DebugHandler is an http.Handler that serves a debugging "homepage",
// and provides helpers to register more debug endpoints and reports.
//
// The rendered page consists of three sections: informational
// key/value pairs, links to other pages, and additional
// program-specific HTML. Callers can add to these sections using the
// KV, URL and Section helpers respectively.
//
// Additionally, the Handle method offers a shorthand for correctly
// registering debug handlers and cross-linking them from /debug/.
type DebugHandler struct {
	mux      *http.ServeMux                   // where this handler is registered
	kvs      []func(io.Writer)                // output one <li>...</li> each, see KV()
	urls     []string                         // one <li>...</li> block with link each
	sections []func(io.Writer, *http.Request) // invoked in registration order prior to outputting </body>
}

// Debugger returns the DebugHandler registered on mux at /debug/,
// creating it if necessary.
func Debugger(mux *http.ServeMux) *DebugHandler {
	h, pat := mux.Handler(&http.Request{URL: &url.URL{Path: "/debug/"}})
	if d, ok := h.(*DebugHandler); ok && pat == "/debug/" {
		return d
	}
	ret := &DebugHandler{
		mux: mux,
	}
	mux.Handle("/debug/", ret)

	ret.KVFunc("Uptime", func() any { return varz.Uptime() })
	ret.KV("Version", version.Long())
	ret.Handle("vars", "Metrics (Go)", expvar.Handler())
	ret.Handle("varz", "Metrics (Prometheus)", http.HandlerFunc(promvarz.Handler))

	// pprof.Index serves everything that runtime/pprof.Lookup finds:
	// goroutine, threadcreate, heap, allocs, block, mutex
	ret.Handle("pprof/", "pprof (index)", http.HandlerFunc(pprof.Index))
	// But register the other ones from net/http/pprof directly:
	ret.HandleSilent("pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	ret.HandleSilent("pprof/profile", http.HandlerFunc(pprof.Profile))
	ret.HandleSilent("pprof/symbol", http.HandlerFunc(pprof.Symbol))
	ret.HandleSilent("pprof/trace", http.HandlerFunc(pprof.Trace))
	ret.URL("/debug/pprof/goroutine?debug=1", "Goroutines (collapsed)")
	ret.URL("/debug/pprof/goroutine?debug=2", "Goroutines (full)")
	ret.Handle("gc", "force GC", http.HandlerFunc(gcHandler))
	hostname, err := os.Hostname()
	if err == nil {
		ret.KV("Machine", hostname)
	}
	return ret
}

// ServeHTTP implements http.Handler.
func (d *DebugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !AllowDebugAccess(r) {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/debug/" {
		// Sub-handlers are handled by the parent mux directly.
		http.NotFound(w, r)
		return
	}

	AddBrowserHeaders(w)
	f := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	f("<html><body><h1>%s debug</h1><ul>", version.CmdName())
	for _, kv := range d.kvs {
		kv(w)
	}
	for _, url := range d.urls {
		io.WriteString(w, url)
	}
	for _, section := range d.sections {
		section(w, r)
	}
}

func (d *DebugHandler) handle(slug string, handler http.Handler) string {
	href := "/debug/" + slug
	d.mux.Handle(href, Protected(debugBrowserHeaderHandler(handler)))
	return href
}

// Handle registers handler at /debug/<slug> and creates a descriptive
// entry in /debug/ for it.
func (d *DebugHandler) Handle(slug, desc string, handler http.Handler) {
	href := d.handle(slug, handler)
	d.URL(href, desc)
}

// HandleSilent registers handler at /debug/<slug>. It does not create
// a descriptive entry in /debug/ for it. This should be used
// sparingly, for things that need to be registered but would pollute
// the list of debug links.
func (d *DebugHandler) HandleSilent(slug string, handler http.Handler) {
	d.handle(slug, handler)
}

// KV adds a key/value list item to /debug/.
func (d *DebugHandler) KV(k string, v any) {
	val := html.EscapeString(fmt.Sprintf("%v", v))
	d.kvs = append(d.kvs, func(w io.Writer) {
		fmt.Fprintf(w, "<li><b>%s:</b> %s</li>", k, val)
	})
}

// KVFunc adds a key/value list item to /debug/. v is called on every
// render of /debug/.
func (d *DebugHandler) KVFunc(k string, v func() any) {
	d.kvs = append(d.kvs, func(w io.Writer) {
		val := html.EscapeString(fmt.Sprintf("%v", v()))
		fmt.Fprintf(w, "<li><b>%s:</b> %s</li>", k, val)
	})
}

// URL adds a URL and description list item to /debug/.
func (d *DebugHandler) URL(url, desc string) {
	if desc != "" {
		desc = " (" + desc + ")"
	}
	d.urls = append(d.urls, fmt.Sprintf(`<li><a href="%s">%s</a>%s</li>`, url, url, html.EscapeString(desc)))
}

// Section invokes f on every render of /debug/ to add supplemental
// HTML to the page body.
func (d *DebugHandler) Section(f func(w io.Writer, r *http.Request)) {
	d.sections = append(d.sections, f)
}

func gcHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("running GC...\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	runtime.GC()
	w.Write([]byte("Done.\n"))
}

// debugBrowserHeaderHandler is a wrapper around BrowserHeaderHandler with a
// more relaxed Content-Security-Policy that's acceptable for internal debug
// pages. It should not be used on any public-facing handlers!
func debugBrowserHeaderHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AddBrowserHeaders(w)
		// The only difference from AddBrowserHeaders is that this policy
		// allows inline CSS styles. They make debug pages much easier to
		// prototype, while the risk of user-injected CSS is relatively low.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; block-all-mixed-content; object-src 'none'; style-src 'self' 'unsafe-inline'")
		h.ServeHTTP(w, r)
	})
}
