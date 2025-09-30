// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !ts_omit_debugeventbus

package eventbus

import (
	"bytes"
	"cmp"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"tailscale.com/tsweb"
)

type httpDebugger struct {
	*Debugger
}

func (d *Debugger) RegisterHTTP(td *tsweb.DebugHandler) {
	dh := httpDebugger{d}
	td.Handle("bus", "Event bus", dh)
	td.HandleSilent("bus/monitor", http.HandlerFunc(dh.serveMonitor))
	td.HandleSilent("bus/style.css", serveStatic("style.css"))
	td.HandleSilent("bus/htmx.min.js", serveStatic("htmx.min.js.gz"))
	td.HandleSilent("bus/htmx-websocket.min.js", serveStatic("htmx-websocket.min.js.gz"))
}

//go:embed assets/*.html
var templatesSrc embed.FS

var templates = sync.OnceValue(func() *template.Template {
	d, err := fs.Sub(templatesSrc, "assets")
	if err != nil {
		panic(fmt.Errorf("getting eventbus debughttp templates subdir: %w", err))
	}
	ret := template.New("").Funcs(map[string]any{
		"prettyPrintStruct": prettyPrintStruct,
	})
	return template.Must(ret.ParseFS(d, "*"))
})

//go:generate go run fetch-htmx.go

//go:embed assets/*.css assets/*.min.js.gz
var static embed.FS

func serveStatic(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(name, ".css"):
			w.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(name, ".min.js.gz"):
			w.Header().Set("Content-Type", "text/javascript")
			w.Header().Set("Content-Encoding", "gzip")
		case strings.HasSuffix(name, ".js"):
			w.Header().Set("Content-Type", "text/javascript")
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		f, err := static.Open(filepath.Join("assets", name))
		if err != nil {
			http.Error(w, fmt.Sprintf("opening asset: %v", err), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, fmt.Sprintf("serving asset: %v", err), http.StatusInternalServerError)
			return
		}
	})
}

func render(w http.ResponseWriter, name string, data any) {
	err := templates().ExecuteTemplate(w, name+".html", data)
	if err != nil {
		err := fmt.Errorf("rendering template: %v", err)
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h httpDebugger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	type clientInfo struct {
		*Client
		Publish   []reflect.Type
		Subscribe []reflect.Type
	}
	type typeInfo struct {
		reflect.Type
		Publish   []*Client
		Subscribe []*Client
	}
	type info struct {
		*Debugger
		Clients map[string]*clientInfo
		Types   map[string]*typeInfo
	}

	data := info{
		Debugger: h.Debugger,
		Clients:  map[string]*clientInfo{},
		Types:    map[string]*typeInfo{},
	}

	getTypeInfo := func(t reflect.Type) *typeInfo {
		if data.Types[t.Name()] == nil {
			data.Types[t.Name()] = &typeInfo{
				Type: t,
			}
		}
		return data.Types[t.Name()]
	}

	for _, c := range h.Clients() {
		ci := &clientInfo{
			Client:    c,
			Publish:   h.PublishTypes(c),
			Subscribe: h.SubscribeTypes(c),
		}
		slices.SortFunc(ci.Publish, func(a, b reflect.Type) int { return cmp.Compare(a.Name(), b.Name()) })
		slices.SortFunc(ci.Subscribe, func(a, b reflect.Type) int { return cmp.Compare(a.Name(), b.Name()) })
		data.Clients[c.Name()] = ci

		for _, t := range ci.Publish {
			ti := getTypeInfo(t)
			ti.Publish = append(ti.Publish, c)
		}
		for _, t := range ci.Subscribe {
			ti := getTypeInfo(t)
			ti.Subscribe = append(ti.Subscribe, c)
		}
	}

	render(w, "main", data)
}

func (h httpDebugger) serveMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") == "websocket" {
		h.serveMonitorStream(w, r)
		return
	}

	render(w, "monitor", nil)
}

func (h httpDebugger) serveMonitorStream(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	wsCtx := conn.CloseRead(r.Context())

	mon := h.WatchBus()
	defer mon.Close()

	i := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-wsCtx.Done():
			return
		case <-mon.Done():
			return
		case event := <-mon.Events():
			msg, err := conn.Writer(r.Context(), websocket.MessageText)
			if err != nil {
				return
			}
			data := map[string]any{
				"Count": i,
				"Type":  reflect.TypeOf(event.Event),
				"Event": event,
			}
			i++
			if err := templates().ExecuteTemplate(msg, "event.html", data); err != nil {
				log.Println(err)
				return
			}
			if err := msg.Close(); err != nil {
				return
			}
		}
	}
}

func prettyPrintStruct(t reflect.Type) string {
	if t.Kind() != reflect.Struct {
		return t.String()
	}
	var rec func(io.Writer, int, reflect.Type)
	rec = func(out io.Writer, indent int, t reflect.Type) {
		ind := strings.Repeat("    ", indent)
		fmt.Fprintf(out, "%s", t.String())
		fs := collectFields(t)
		if len(fs) > 0 {
			io.WriteString(out, " {\n")
			for _, f := range fs {
				fmt.Fprintf(out, "%s    %s ", ind, f.Name)
				if f.Type.Kind() == reflect.Struct {
					rec(out, indent+1, f.Type)
				} else {
					fmt.Fprint(out, f.Type)
				}
				io.WriteString(out, "\n")
			}
			fmt.Fprintf(out, "%s}", ind)
		}
	}

	var ret bytes.Buffer
	rec(&ret, 0, t)
	return ret.String()
}

func collectFields(t reflect.Type) (ret []reflect.StructField) {
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() {
			continue
		}
		ret = append(ret, f)
	}
	return ret
}
