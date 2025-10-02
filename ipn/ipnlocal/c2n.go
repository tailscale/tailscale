// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/sockstats"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/httpm"
	"tailscale.com/util/set"
	"tailscale.com/version"
)

// c2nHandlers maps an HTTP method and URI path (without query parameters) to
// its handler. The exact method+path match is preferred, but if no entry
// exists for that, a map entry with an empty method is used as a fallback.
var c2nHandlers map[methodAndPath]c2nHandler

func init() {
	c2nHandlers = map[methodAndPath]c2nHandler{}
	if buildfeatures.HasC2N {
		// Echo is the basic "ping" handler as used by the control plane to probe
		// whether a node is reachable. In particular, it's important for
		// high-availability subnet routers for the control plane to probe which of
		// several candidate nodes is reachable and actually alive.
		RegisterC2N("/echo", handleC2NEcho)
	}
	if buildfeatures.HasSSH {
		RegisterC2N("/ssh/usernames", handleC2NSSHUsernames)
	}
	if buildfeatures.HasLogTail {
		RegisterC2N("POST /logtail/flush", handleC2NLogtailFlush)
	}
	if buildfeatures.HasDebug {
		RegisterC2N("POST /sockstats", handleC2NSockStats)

		// pprof:
		// we only expose a subset of typical pprof endpoints for security.
		RegisterC2N("/debug/pprof/heap", handleC2NPprof)
		RegisterC2N("/debug/pprof/allocs", handleC2NPprof)

		RegisterC2N("/debug/goroutines", handleC2NDebugGoroutines)
		RegisterC2N("/debug/prefs", handleC2NDebugPrefs)
		RegisterC2N("/debug/metrics", handleC2NDebugMetrics)
		RegisterC2N("/debug/component-logging", handleC2NDebugComponentLogging)
		RegisterC2N("/debug/logheap", handleC2NDebugLogHeap)
		RegisterC2N("/debug/netmap", handleC2NDebugNetMap)
		RegisterC2N("/debug/health", handleC2NDebugHealth)
	}
	if runtime.GOOS == "linux" && buildfeatures.HasOSRouter {
		RegisterC2N("POST /netfilter-kind", handleC2NSetNetfilterKind)
	}
}

// RegisterC2N registers a new c2n handler for the given pattern.
//
// A pattern is like "GET /foo" (specific to an HTTP method) or "/foo" (all
// methods). It panics if the pattern is already registered.
func RegisterC2N(pattern string, h func(*LocalBackend, http.ResponseWriter, *http.Request)) {
	if !buildfeatures.HasC2N {
		return
	}
	k := req(pattern)
	if _, ok := c2nHandlers[k]; ok {
		panic(fmt.Sprintf("c2n: duplicate handler for %q", pattern))
	}
	c2nHandlers[k] = h
}

type c2nHandler func(*LocalBackend, http.ResponseWriter, *http.Request)

type methodAndPath struct {
	method string // empty string means fallback
	path   string // Request.URL.Path (without query string)
}

func req(s string) methodAndPath {
	if m, p, ok := strings.Cut(s, " "); ok {
		return methodAndPath{m, p}
	}
	return methodAndPath{"", s}
}

// c2nHandlerPaths is all the set of paths from c2nHandlers, without their HTTP methods.
// It's used to detect requests with a non-matching method.
var c2nHandlerPaths = set.Set[string]{}

func init() {
	for k := range c2nHandlers {
		c2nHandlerPaths.Add(k.path)
	}
}

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	// First try to match by both method and path,
	if h, ok := c2nHandlers[methodAndPath{r.Method, r.URL.Path}]; ok {
		h(b, w, r)
		return
	}
	// Then try to match by just path.
	if h, ok := c2nHandlers[methodAndPath{path: r.URL.Path}]; ok {
		h(b, w, r)
		return
	}
	if c2nHandlerPaths.Contains(r.URL.Path) {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
	} else {
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func handleC2NEcho(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	// Test handler.
	body, _ := io.ReadAll(r.Body)
	w.Write(body)
}

func handleC2NLogtailFlush(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if b.TryFlushLogs() {
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "no log flusher wired up", http.StatusInternalServerError)
	}
}

func handleC2NDebugHealth(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	var st *health.State
	if buildfeatures.HasDebug && b.health != nil {
		st = b.health.CurrentState()
	}
	writeJSON(w, st)
}

func handleC2NDebugNetMap(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	ctx := r.Context()
	if r.Method != httpm.POST && r.Method != httpm.GET {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	b.logf("c2n: %s /debug/netmap received", r.Method)

	// redactAndMarshal redacts private keys from the given netmap, clears fields
	// that should be omitted, and marshals it to JSON.
	redactAndMarshal := func(nm *netmap.NetworkMap, omitFields []string) (json.RawMessage, error) {
		for _, f := range omitFields {
			field := reflect.ValueOf(nm).Elem().FieldByName(f)
			if !field.IsValid() {
				b.logf("c2n: /debug/netmap: unknown field %q in omitFields", f)
				continue
			}
			field.SetZero()
		}
		nm, _ = redactNetmapPrivateKeys(nm)
		return json.Marshal(nm)
	}

	var omitFields []string
	resp := &tailcfg.C2NDebugNetmapResponse{}

	if r.Method == httpm.POST {
		var req tailcfg.C2NDebugNetmapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode request body: %v", err), http.StatusBadRequest)
			return
		}
		omitFields = req.OmitFields

		if req.Candidate != nil {
			cand, err := controlclient.NetmapFromMapResponseForDebug(ctx, b.unsanitizedPersist(), req.Candidate)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to convert candidate MapResponse: %v", err), http.StatusBadRequest)
				return
			}
			candJSON, err := redactAndMarshal(cand, omitFields)
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to marshal candidate netmap: %v", err), http.StatusInternalServerError)
				return
			}
			resp.Candidate = candJSON
		}
	}

	var err error
	resp.Current, err = redactAndMarshal(b.currentNode().netMapWithPeers(), omitFields)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal current netmap: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func handleC2NDebugGoroutines(_ *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(goroutines.ScrubbedGoroutineDump(true))
}

func handleC2NDebugPrefs(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	writeJSON(w, b.Prefs())
}

func handleC2NDebugMetrics(_ *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	clientmetric.WritePrometheusExpositionFormat(w)
}

func handleC2NDebugComponentLogging(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	component := r.FormValue("component")
	secs, _ := strconv.Atoi(r.FormValue("secs"))
	if secs == 0 {
		secs -= 1
	}
	until := b.clock.Now().Add(time.Duration(secs) * time.Second)
	err := b.SetComponentDebugLogging(component, until)
	var res struct {
		Error string `json:",omitempty"`
	}
	if err != nil {
		res.Error = err.Error()
	}
	writeJSON(w, res)
}

var c2nLogHeap func(http.ResponseWriter, *http.Request) // non-nil on most platforms (c2n_pprof.go)

func handleC2NDebugLogHeap(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if c2nLogHeap == nil {
		// Not implemented on platforms trying to optimize for binary size or
		// reduced memory usage.
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}
	c2nLogHeap(w, r)
}

var c2nPprof func(http.ResponseWriter, *http.Request, string) // non-nil on most platforms (c2n_pprof.go)

func handleC2NPprof(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if c2nPprof == nil {
		// Not implemented on platforms trying to optimize for binary size or
		// reduced memory usage.
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}
	_, profile := path.Split(r.URL.Path)
	c2nPprof(w, r, profile)
}

func handleC2NSSHUsernames(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasSSH {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	var req tailcfg.C2NSSHUsernamesRequest
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	res, err := b.getSSHUsernames(&req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, res)
}

func handleC2NSockStats(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if b.sockstatLogger == nil {
		http.Error(w, "no sockstatLogger", http.StatusInternalServerError)
		return
	}
	b.sockstatLogger.Flush()
	fmt.Fprintf(w, "logid: %s\n", b.sockstatLogger.LogID())
	fmt.Fprintf(w, "debug info: %v\n", sockstats.DebugInfo())
}

func handleC2NSetNetfilterKind(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: POST /netfilter-kind received")

	if version.OS() != "linux" {
		http.Error(w, "netfilter kind only settable on linux", http.StatusNotImplemented)
	}

	kind := r.FormValue("kind")
	b.logf("c2n: switching netfilter to %s", kind)

	_, err := b.EditPrefs(&ipn.MaskedPrefs{
		NetfilterKindSet: true,
		Prefs: ipn.Prefs{
			NetfilterKind: kind,
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b.authReconfig()

	w.WriteHeader(http.StatusNoContent)
}
