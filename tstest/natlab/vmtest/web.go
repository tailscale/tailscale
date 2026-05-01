// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"embed"
	"flag"
	"fmt"
	"hash/crc32"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/robert-nix/ansihtml"
)

var vmtestWeb = flag.String("vmtest-web", "", "listen address for vmtest web UI (e.g. :0, localhost:0, :8080)")

//go:embed assets/*.html
var templatesSrc embed.FS

//go:embed assets/*.css
var staticAssets embed.FS

var tmpl = sync.OnceValue(func() *template.Template {
	d, err := fs.Sub(templatesSrc, "assets")
	if err != nil {
		panic(fmt.Errorf("getting vmtest web templates subdir: %w", err))
	}
	return template.Must(template.New("").Funcs(template.FuncMap{
		"formatDuration": formatDuration,
		"ansi":           ansiToHTML,
	}).ParseFS(d, "*"))
})

// ansiToHTML converts a string with ANSI escape sequences to HTML with
// inline styles. Returns template.HTML so html/template doesn't double-escape it.
func ansiToHTML(s string) template.HTML {
	return template.HTML(ansihtml.ConvertToHTML([]byte(s)))
}

// formatDuration returns a human-readable duration like "1.2s" or "45.3s".
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// deterministicPort returns a deterministic port in the range [20000, 40000)
// based on the test name, so re-running the same test gets the same URL.
func deterministicPort(testName string) int {
	return int(crc32.ChecksumIEEE([]byte(testName)))%20000 + 20000
}

// listenWeb listens on the given address. If the port is 0, it first tries a
// deterministic port based on the test name so re-runs get the same URL.
// Falls back to :0 (OS-assigned) on any listen error.
func (e *Env) listenWeb(addr string) (net.Listener, error) {
	host, port, _ := net.SplitHostPort(addr)
	if port == "0" {
		detPort := deterministicPort(e.t.Name())
		detAddr := net.JoinHostPort(host, fmt.Sprintf("%d", detPort))
		if ln, err := net.Listen("tcp", detAddr); err == nil {
			return ln, nil
		}
		// Deterministic port busy; fall back to OS-assigned.
	}
	return net.Listen("tcp", addr)
}

// maybeStartWebServer starts the web UI if --vmtest-web is set.
// Called at the very top of Env.Start(), before compilation or image downloads.
func (e *Env) maybeStartWebServer() {
	addr := *vmtestWeb
	if addr == "" {
		return
	}

	ln, err := e.listenWeb(addr)
	if err != nil {
		e.t.Fatalf("vmtest-web listen: %v", err)
	}
	e.t.Cleanup(func() { ln.Close() })

	actualAddr := ln.Addr().(*net.TCPAddr)

	host, _, _ := net.SplitHostPort(addr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "localhost"
		}
		e.t.Logf("Status at http://%s:%d/", hostname, actualAddr.Port)
	} else {
		e.t.Logf("Status at http://%s/", actualAddr.String())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", e.serveIndex)
	mux.HandleFunc("GET /ws", e.serveWebSocket)
	mux.HandleFunc("GET /screenshot/{node}", e.serveScreenshot)
	mux.HandleFunc("GET /style.css", serveStaticAsset("style.css"))

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	e.t.Cleanup(func() { srv.Close() })
}

func serveStaticAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(name, ".css") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/css")
		f, err := staticAssets.Open(filepath.Join("assets", name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	}
}

func (e *Env) serveIndex(w http.ResponseWriter, r *http.Request) {
	type indexData struct {
		TestName   string
		TestStatus *TestStatus
		Steps      []*Step
		Nodes      []NodeStatus
	}

	data := indexData{
		TestName:   e.t.Name(),
		TestStatus: e.testStatus,
		Steps:      e.Steps(),
	}
	for _, n := range e.nodes {
		data.Nodes = append(data.Nodes, e.getNodeStatus(n.name))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl().ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// serveScreenshot proxies a full-resolution screenshot from the Host.app
// screenshot server. Returns raw JPEG with no HTML wrapper.
func (e *Env) serveScreenshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("node")
	port := e.nodeScreenshotPort(name)
	if port == 0 {
		http.Error(w, "no screenshot server for node", http.StatusNotFound)
		return
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/screenshot?full=1", port))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "image/jpeg")
	io.Copy(w, resp.Body)
}

func (e *Env) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	wsCtx := conn.CloseRead(r.Context())

	sub := e.eventBus.Subscribe()
	defer sub.Close()

	for {
		select {
		case <-wsCtx.Done():
			return
		case <-sub.Done():
			return
		case ev := <-sub.Events():
			msg, err := conn.Writer(r.Context(), websocket.MessageText)
			if err != nil {
				return
			}
			if err := tmpl().ExecuteTemplate(msg, "event.html", ev); err != nil {
				msg.Close()
				return
			}
			if err := msg.Close(); err != nil {
				return
			}
		}
	}
}
