// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tailscale.com/clientupdate"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/sockstats"
	"tailscale.com/posture"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/httpm"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

// c2nHandlers maps an HTTP method and URI path (without query parameters) to
// its handler. The exact method+path match is preferred, but if no entry
// exists for that, a map entry with an empty method is used as a fallback.
var c2nHandlers = map[methodAndPath]c2nHandler{
	// Debug.
	req("/echo"):                    handleC2NEcho,
	req("/debug/goroutines"):        handleC2NDebugGoroutines,
	req("/debug/prefs"):             handleC2NDebugPrefs,
	req("/debug/metrics"):           handleC2NDebugMetrics,
	req("/debug/component-logging"): handleC2NDebugComponentLogging,
	req("/debug/logheap"):           handleC2NDebugLogHeap,
	req("/debug/netmap"):            handleC2NDebugNetMap,

	// PPROF - We only expose a subset of typical pprof endpoints for security.
	req("/debug/pprof/heap"):   handleC2NPprof,
	req("/debug/pprof/allocs"): handleC2NPprof,

	req("POST /logtail/flush"): handleC2NLogtailFlush,
	req("POST /sockstats"):     handleC2NSockStats,

	// SSH
	req("/ssh/usernames"): handleC2NSSHUsernames,

	// Auto-updates.
	req("GET /update"):  handleC2NUpdateGet,
	req("POST /update"): handleC2NUpdatePost,

	// Device posture.
	req("GET /posture/identity"): handleC2NPostureIdentityGet,

	// App Connectors.
	req("GET /appconnector/routes"): handleC2NAppConnectorDomainRoutesGet,

	// Linux netfilter.
	req("POST /netfilter-kind"): handleC2NSetNetfilterKind,
}

// RegisterC2N registers a new c2n handler for the given pattern.
//
// A pattern is like "GET /foo" (specific to an HTTP method) or "/foo" (all
// methods). It panics if the pattern is already registered.
func RegisterC2N(pattern string, h func(*LocalBackend, http.ResponseWriter, *http.Request)) {
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

func handleC2NDebugNetMap(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "text/plain")
	w.Write(goroutines.ScrubbedGoroutineDump(true))
}

func handleC2NDebugPrefs(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	writeJSON(w, b.Prefs())
}

func handleC2NDebugMetrics(_ *LocalBackend, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	clientmetric.WritePrometheusExpositionFormat(w)
}

func handleC2NDebugComponentLogging(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
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

// handleC2NAppConnectorDomainRoutesGet handles returning the domains
// that the app connector is responsible for, as well as the resolved
// IP addresses for each domain. If the node is not configured as
// an app connector, an empty map is returned.
func handleC2NAppConnectorDomainRoutesGet(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /appconnector/routes received")

	var res tailcfg.C2NAppConnectorDomainRoutesResponse
	appConnector := b.AppConnector()
	if appConnector == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Domains = appConnector.DomainRoutes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
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

func handleC2NUpdateGet(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /update received")

	res := b.newC2NUpdateResponse()
	res.Started = b.c2nUpdateStarted()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleC2NUpdatePost(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: POST /update received")
	res := b.newC2NUpdateResponse()
	defer func() {
		if res.Err != "" {
			b.logf("c2n: POST /update failed: %s", res.Err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}()

	if !res.Enabled {
		res.Err = "not enabled"
		return
	}
	if !res.Supported {
		res.Err = "not supported"
		return
	}

	// Do not update if we have active inbound SSH connections. Control can set
	// force=true query parameter to override this.
	if r.FormValue("force") != "true" && b.sshServer != nil && b.sshServer.NumActiveConns() > 0 {
		res.Err = "not updating due to active SSH connections"
		return
	}

	if err := b.startAutoUpdate("c2n"); err != nil {
		res.Err = err.Error()
		return
	}
	res.Started = true
}

func handleC2NPostureIdentityGet(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /posture/identity received")

	res := tailcfg.C2NPostureIdentityResponse{}

	// Only collect posture identity if enabled on the client,
	// this will first check syspolicy, MDM settings like Registry
	// on Windows or defaults on macOS. If they are not set, it falls
	// back to the cli-flag, `--posture-checking`.
	choice, err := b.polc.GetPreferenceOption(pkey.PostureChecking, ptype.ShowChoiceByPolicy)
	if err != nil {
		b.logf(
			"c2n: failed to read PostureChecking from syspolicy, returning default from CLI: %s; got error: %s",
			b.Prefs().PostureChecking(),
			err,
		)
	}

	if choice.ShouldEnable(b.Prefs().PostureChecking()) {
		res.SerialNumbers, err = posture.GetSerialNumbers(b.polc, b.logf)
		if err != nil {
			b.logf("c2n: GetSerialNumbers returned error: %v", err)
		}

		// TODO(tailscale/corp#21371, 2024-07-10): once this has landed in a stable release
		// and looks good in client metrics, remove this parameter and always report MAC
		// addresses.
		if r.FormValue("hwaddrs") == "true" {
			res.IfaceHardwareAddrs, err = b.getHardwareAddrs()
			if err != nil {
				b.logf("c2n: GetHardwareAddrs returned error: %v", err)
			}
		}
	} else {
		res.PostureDisabled = true
	}

	b.logf("c2n: posture identity disabled=%v reported %d serials %d hwaddrs", res.PostureDisabled, len(res.SerialNumbers), len(res.IfaceHardwareAddrs))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (b *LocalBackend) newC2NUpdateResponse() tailcfg.C2NUpdateResponse {
	// If NewUpdater does not return an error, we can update the installation.
	//
	// Note that we create the Updater solely to check for errors; we do not
	// invoke it here. For this purpose, it is ok to pass it a zero Arguments.
	prefs := b.Prefs().AutoUpdate()
	return tailcfg.C2NUpdateResponse{
		Enabled:   envknob.AllowsRemoteUpdate() || prefs.Apply.EqualBool(true),
		Supported: clientupdate.CanAutoUpdate() && !version.IsMacSysExt(),
	}
}

func (b *LocalBackend) c2nUpdateStarted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.c2nUpdateStatus.started
}

func (b *LocalBackend) setC2NUpdateStarted(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.c2nUpdateStatus.started = v
}

func (b *LocalBackend) trySetC2NUpdateStarted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c2nUpdateStatus.started {
		return false
	}
	b.c2nUpdateStatus.started = true
	return true
}

// findCmdTailscale looks for the cmd/tailscale that corresponds to the
// currently running cmd/tailscaled. It's up to the caller to verify that the
// two match, but this function does its best to find the right one. Notably, it
// doesn't use $PATH for security reasons.
func findCmdTailscale() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	var ts string
	switch runtime.GOOS {
	case "linux":
		if self == "/usr/sbin/tailscaled" || self == "/usr/bin/tailscaled" {
			ts = "/usr/bin/tailscale"
		}
		if self == "/usr/local/sbin/tailscaled" || self == "/usr/local/bin/tailscaled" {
			ts = "/usr/local/bin/tailscale"
		}
		switch distro.Get() {
		case distro.QNAP:
			// The volume under /share/ where qpkg are installed is not
			// predictable. But the rest of the path is.
			ok, err := filepath.Match("/share/*/.qpkg/Tailscale/tailscaled", self)
			if err == nil && ok {
				ts = filepath.Join(filepath.Dir(self), "tailscale")
			}
		case distro.Unraid:
			if self == "/usr/local/emhttp/plugins/tailscale/bin/tailscaled" {
				ts = "/usr/local/emhttp/plugins/tailscale/bin/tailscale"
			}
		}
	case "windows":
		ts = filepath.Join(filepath.Dir(self), "tailscale.exe")
	case "freebsd", "openbsd":
		if self == "/usr/local/bin/tailscaled" {
			ts = "/usr/local/bin/tailscale"
		}
	default:
		return "", fmt.Errorf("unsupported OS %v", runtime.GOOS)
	}
	if ts != "" && regularFileExists(ts) {
		return ts, nil
	}
	return "", errors.New("tailscale executable not found in expected place")
}

func tailscaleUpdateCmd(cmdTS string) *exec.Cmd {
	defaultCmd := exec.Command(cmdTS, "update", "--yes")
	if runtime.GOOS != "linux" {
		return defaultCmd
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return defaultCmd
	}

	// When systemd-run is available, use it to run the update command. This
	// creates a new temporary unit separate from the tailscaled unit. When
	// tailscaled is restarted during the update, systemd won't kill this
	// temporary update unit, which could cause unexpected breakage.
	//
	// We want to use a few optional flags:
	//  * --wait, to block the update command until completion (added in systemd 232)
	//  * --pipe, to collect stdout/stderr (added in systemd 235)
	//  * --collect, to clean up failed runs from memory (added in systemd 236)
	//
	// We need to check the version of systemd to figure out if those flags are
	// available.
	//
	// The output will look like:
	//
	//   systemd 255 (255.7-1-arch)
	//   +PAM +AUDIT ... other feature flags ...
	systemdVerOut, err := exec.Command("systemd-run", "--version").Output()
	if err != nil {
		return defaultCmd
	}
	parts := strings.Fields(string(systemdVerOut))
	if len(parts) < 2 || parts[0] != "systemd" {
		return defaultCmd
	}
	systemdVer, err := strconv.Atoi(parts[1])
	if err != nil {
		return defaultCmd
	}
	if systemdVer >= 236 {
		return exec.Command("systemd-run", "--wait", "--pipe", "--collect", cmdTS, "update", "--yes")
	} else if systemdVer >= 235 {
		return exec.Command("systemd-run", "--wait", "--pipe", cmdTS, "update", "--yes")
	} else if systemdVer >= 232 {
		return exec.Command("systemd-run", "--wait", cmdTS, "update", "--yes")
	} else {
		return exec.Command("systemd-run", cmdTS, "update", "--yes")
	}
}

func regularFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
