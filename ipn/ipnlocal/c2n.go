// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kortschak/wol"
	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/sockstats"
	"tailscale.com/posture"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy"
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

	// PPROF - We only expose a subset of typical pprof endpoints for security.
	req("/debug/pprof/heap"):   handleC2NPprof,
	req("/debug/pprof/allocs"): handleC2NPprof,

	req("POST /logtail/flush"): handleC2NLogtailFlush,
	req("POST /sockstats"):     handleC2NSockStats,

	// Check TLS certificate status.
	req("GET /tls-cert-status"): handleC2NTLSCertStatus,

	// SSH
	req("/ssh/usernames"): handleC2NSSHUsernames,

	// Auto-updates.
	req("GET /update"):  handleC2NUpdateGet,
	req("POST /update"): handleC2NUpdatePost,

	// Wake-on-LAN.
	req("POST /wol"): handleC2NWoL,

	// Device posture.
	req("GET /posture/identity"): handleC2NPostureIdentityGet,

	// App Connectors.
	req("GET /appconnector/routes"): handleC2NAppConnectorDomainRoutesGet,

	// Linux netfilter.
	req("POST /netfilter-kind"): handleC2NSetNetfilterKind,
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
	if b.appConnector == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Domains = b.appConnector.DomainRoutes()

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

	// Check if update was already started, and mark as started.
	if !b.trySetC2NUpdateStarted() {
		res.Err = "update already started"
		return
	}
	defer func() {
		// Clear the started flag if something failed.
		if res.Err != "" {
			b.setC2NUpdateStarted(false)
		}
	}()

	cmdTS, err := findCmdTailscale()
	if err != nil {
		res.Err = fmt.Sprintf("failed to find cmd/tailscale binary: %v", err)
		return
	}
	var ver struct {
		Long string `json:"long"`
	}
	out, err := exec.Command(cmdTS, "version", "--json").Output()
	if err != nil {
		res.Err = fmt.Sprintf("failed to find cmd/tailscale binary: %v", err)
		return
	}
	if err := json.Unmarshal(out, &ver); err != nil {
		res.Err = "invalid JSON from cmd/tailscale version --json"
		return
	}
	if ver.Long != version.Long() {
		res.Err = "cmd/tailscale version mismatch"
		return
	}

	cmd := tailscaleUpdateCmd(cmdTS)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = buf
	b.logf("c2n: running %q", strings.Join(cmd.Args, " "))
	if err := cmd.Start(); err != nil {
		res.Err = fmt.Sprintf("failed to start cmd/tailscale update: %v", err)
		return
	}
	res.Started = true

	// Run update asynchronously and respond that it started.
	go func() {
		if err := cmd.Wait(); err != nil {
			b.logf("c2n: update command failed: %v, output: %s", err, buf)
		} else {
			b.logf("c2n: update complete")
		}
		b.setC2NUpdateStarted(false)
	}()
}

func handleC2NPostureIdentityGet(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /posture/identity received")

	res := tailcfg.C2NPostureIdentityResponse{}

	// Only collect serial numbers if enabled on the client,
	// this will first check syspolicy, MDM settings like Registry
	// on Windows or defaults on macOS. If they are not set, it falls
	// back to the cli-flag, `--posture-checking`.
	choice, err := syspolicy.GetPreferenceOption(syspolicy.PostureChecking)
	if err != nil {
		b.logf(
			"c2n: failed to read PostureChecking from syspolicy, returning default from CLI: %s; got error: %s",
			b.Prefs().PostureChecking(),
			err,
		)
	}

	if choice.ShouldEnable(b.Prefs().PostureChecking()) {
		sns, err := posture.GetSerialNumbers(b.logf)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res.SerialNumbers = sns
	} else {
		res.PostureDisabled = true
	}

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
		Supported: clientupdate.CanAutoUpdate(),
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
	case "freebsd":
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
	if runtime.GOOS != "linux" {
		return exec.Command(cmdTS, "update", "--yes")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return exec.Command(cmdTS, "update", "--yes")
	}
	// When systemd-run is available, use it to run the update command. This
	// creates a new temporary unit separate from the tailscaled unit. When
	// tailscaled is restarted during the update, systemd won't kill this
	// temporary update unit, which could cause unexpected breakage.
	return exec.Command("systemd-run", "--wait", "--pipe", "--collect", cmdTS, "update", "--yes")
}

func regularFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func handleC2NWoL(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var macs []net.HardwareAddr
	for _, macStr := range r.Form["mac"] {
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			http.Error(w, "bad 'mac' param", http.StatusBadRequest)
			return
		}
		macs = append(macs, mac)
	}
	var res struct {
		SentTo []string
		Errors []string
	}
	st := b.sys.NetMon.Get().InterfaceState()
	if st == nil {
		res.Errors = append(res.Errors, "no interface state")
		writeJSON(w, &res)
		return
	}
	var password []byte // TODO(bradfitz): support? does anything use WoL passwords?
	for _, mac := range macs {
		for ifName, ips := range st.InterfaceIPs {
			for _, ip := range ips {
				if ip.Addr().IsLoopback() || ip.Addr().Is6() {
					continue
				}
				local := &net.UDPAddr{
					IP:   ip.Addr().AsSlice(),
					Port: 0,
				}
				remote := &net.UDPAddr{
					IP:   net.IPv4bcast,
					Port: 0,
				}
				if err := wol.Wake(mac, password, local, remote); err != nil {
					res.Errors = append(res.Errors, err.Error())
				} else {
					res.SentTo = append(res.SentTo, ifName)
				}
				break // one per interface is enough
			}
		}
	}
	sort.Strings(res.SentTo)
	writeJSON(w, &res)
}

// handleC2NTLSCertStatus returns info about the last TLS certificate issued for the
// provided domain. This can be called by the controlplane to clean up DNS TXT
// records when they're no longer needed by LetsEncrypt.
//
// It does not kick off a cert fetch or async refresh. It only reports anything
// that's already sitting on disk, and only reports metadata about the public
// cert (stuff that'd be the in CT logs anyway).
func handleC2NTLSCertStatus(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	cs, err := b.getCertStore()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "no 'domain'", http.StatusBadRequest)
		return
	}

	ret := &tailcfg.C2NTLSCertInfo{}
	pair, err := getCertPEMCached(cs, domain, b.clock.Now())
	ret.Valid = err == nil
	if err != nil {
		ret.Error = err.Error()
		if errors.Is(err, errCertExpired) {
			ret.Expired = true
		} else if errors.Is(err, ipn.ErrStateNotExist) {
			ret.Missing = true
			ret.Error = "no certificate"
		}
	} else {
		block, _ := pem.Decode(pair.CertPEM)
		if block == nil {
			ret.Error = "invalid PEM"
			ret.Valid = false
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ret.Error = fmt.Sprintf("invalid certificate: %v", err)
				ret.Valid = false
			} else {
				ret.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
				ret.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
			}
		}
	}

	writeJSON(w, ret)
}
