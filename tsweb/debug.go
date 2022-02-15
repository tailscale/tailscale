// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"expvar"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

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
	flagmu   sync.Mutex                       // flagmu protects access to flagset and flagc
	flagset  *flag.FlagSet                    // runtime-modifiable flags, may be nil
	flagc    chan map[string]interface{}      // DebugHandler sends new flag values on flagc when the flags have been modified
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

	// Register this one directly on mux, rather than using
	// ret.URL/etc, as we don't need another line of output on the
	// index page. The /pprof/ index already covers it.
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))

	ret.KVFunc("Uptime", func() interface{} { return Uptime() })
	ret.KV("Version", version.Long)
	ret.Handle("vars", "Metrics (Go)", expvar.Handler())
	ret.Handle("varz", "Metrics (Prometheus)", http.HandlerFunc(VarzHandler))
	ret.Handle("pprof/", "pprof", http.HandlerFunc(pprof.Index))
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

	f := func(format string, args ...interface{}) { fmt.Fprintf(w, format, args...) }
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

// Handle registers handler at /debug/<slug> and creates a descriptive
// entry in /debug/ for it.
func (d *DebugHandler) Handle(slug, desc string, handler http.Handler) {
	href := "/debug/" + slug
	d.mux.Handle(href, Protected(handler))
	d.URL(href, desc)
}

// KV adds a key/value list item to /debug/.
func (d *DebugHandler) KV(k string, v interface{}) {
	val := html.EscapeString(fmt.Sprintf("%v", v))
	d.kvs = append(d.kvs, func(w io.Writer) {
		fmt.Fprintf(w, "<li><b>%s:</b> %s</li>", k, val)
	})
}

// KVFunc adds a key/value list item to /debug/. v is called on every
// render of /debug/.
func (d *DebugHandler) KVFunc(k string, v func() interface{}) {
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

// FlagSet returns a FlagSet that can be used to add runtime-modifiable flags to d.
// Calling code should add flags to fs, but not retain the values directly.
// Modifications to fs will be delivered via c.
// Maps sent to c will be keyed on the flag name, and contain the new value.
// Only modified values will be sent on c.
//
// Sample usage:
//      flagset, flagc := debug.FlagSet()
//      flagset.Int("max", 0, "maximum number of bars")
//      flagset.String("s", "qux", "default name for new foos")
//      go func() {
//          for change := range flagc {
//              // TODO: handle change, which will contain values for keys "max" and/or "s"
//          }
//      }()
func (d *DebugHandler) FlagSet() (fs *flag.FlagSet, c chan map[string]interface{}) {
	d.flagmu.Lock()
	defer d.flagmu.Unlock()
	if d.flagset == nil {
		d.flagset = flag.NewFlagSet("debug", flag.ContinueOnError)
		d.flagc = make(chan map[string]interface{})
		d.Handle("flags", "Runtime flags", http.HandlerFunc(d.handleFlags))
	}
	return d.flagset, d.flagc
}

type copiedFlag struct {
	Name  string
	Value string
	Usage string
}

func copyFlags(fs *flag.FlagSet) []copiedFlag {
	var all []copiedFlag
	fs.VisitAll(func(f *flag.Flag) {
		all = append(all, copiedFlag{Name: f.Name, Value: f.Value.String(), Usage: f.Usage})
	})
	return all
}

func (d *DebugHandler) handleFlags(w http.ResponseWriter, r *http.Request) {
	d.flagmu.Lock()
	defer d.flagmu.Unlock()

	var userError string
	var modified string
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Make a copy of existing values, in case we need to roll back.
		all := copyFlags(d.flagset)
		// Set inbound values.
		changed := make(map[string][2]string)
		rollback := false
		for k, v := range r.PostForm {
			if len(v) != 1 {
				userError = fmt.Sprintf("multiple values for name %q: %q", k, v)
				rollback = true
				break
			}
			f := d.flagset.Lookup(k)
			if f == nil {
				userError = fmt.Sprintf("unknown name %q", k)
				rollback = true
				break
			}
			prev := f.Value.String()
			new := strings.TrimSpace(v[0])
			if prev == new {
				continue
			}
			err := d.flagset.Set(k, new)
			if err != nil {
				userError = fmt.Sprintf("parsing value %q for name %q: %v", new, k, err)
				rollback = true
				break
			}
			changed[k] = [2]string{prev, new}
		}
		if rollback {
			for _, f := range all {
				d.flagset.Set(f.Name, f.Value)
			}
		} else {
			// Generate description of modifications.
			var names []string
			for k := range changed {
				names = append(names, k)
			}
			sort.Strings(names)
			buf := new(strings.Builder)
			for i, k := range names {
				if i != 0 {
					buf.WriteString("; ")
				}
				pn := changed[k]
				fmt.Fprintf(buf, "%q: %v → %v", k, pn[0], pn[1])
			}
			modified = buf.String()
			vals := make(map[string]interface{})
			for _, k := range names {
				vals[k] = d.flagset.Lookup(k).Value.(flag.Getter).Get()
			}

			d.flagc <- vals
			// TODO: post modifications to Slack, along with attribution
		}
	}

	dot := &struct {
		Error    string
		Modified string
		Flags    []copiedFlag
	}{
		Error:    userError,
		Modified: modified,
		Flags:    copyFlags(d.flagset),
	}
	err := flagsTemplate.Execute(w, dot)
	if err != nil {
		log.Print(err)
	}
}

var (
	flagsTemplate = template.Must(template.New("flags").Parse(`
<html>
<body>

{{if .Error}}
<h2>Error: <mark>{{.Error}}</mark></h2>
{{end}}

{{if .Modified}}
<h3>Modified: <mark>{{.Modified}}</mark></h3>
{{end}}

<h3>Modifiable runtime flags</h3>

<p>Warning! Modifying these values will take effect immediately and impact the running service</p>

<form method="POST">
<table>
<tr> <th>Name</th> <th>Value</th> <th>Usage</th> </tr>
{{range .Flags}}
<tr> <td>{{.Name}}</td> <td><input type="text" value="{{.Value}}" name="{{.Name}}"/></td> <td>{{.Usage}}</td> </tr>
{{end}}
</table>
<input type="submit"></input>
</form>
</body>
</html>
`))
)
