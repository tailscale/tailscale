// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kortschak/wol"
	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/net/sockstats"
	"tailscale.com/posture"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/httpm"
	"tailscale.com/util/syspolicy"
	"tailscale.com/version"
)

var c2nLogHeap func(http.ResponseWriter, *http.Request) // non-nil on most platforms (c2n_pprof.go)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/echo":
		// Test handler.
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	case "/update":
		switch r.Method {
		case httpm.GET:
			b.handleC2NUpdateGet(w, r)
		case httpm.POST:
			b.handleC2NUpdatePost(w, r)
		default:
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
	case "/wol":
		b.handleC2NWoL(w, r)
		return
	case "/logtail/flush":
		if r.Method != "POST" {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if b.TryFlushLogs() {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "no log flusher wired up", http.StatusInternalServerError)
		}
	case "/posture/identity":
		switch r.Method {
		case httpm.GET:
			b.handleC2NPostureIdentityGet(w, r)
		default:
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
	case "/debug/goroutines":
		w.Header().Set("Content-Type", "text/plain")
		w.Write(goroutines.ScrubbedGoroutineDump(true))
	case "/debug/prefs":
		writeJSON(w, b.Prefs())
	case "/debug/metrics":
		w.Header().Set("Content-Type", "text/plain")
		clientmetric.WritePrometheusExpositionFormat(w)
	case "/debug/component-logging":
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
	case "/debug/logheap":
		if c2nLogHeap != nil {
			c2nLogHeap(w, r)
		} else {
			http.Error(w, "not implemented", http.StatusNotImplemented)
			return
		}
	case "/ssh/usernames":
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
	case "/sockstats":
		if r.Method != "POST" {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if b.sockstatLogger == nil {
			http.Error(w, "no sockstatLogger", http.StatusInternalServerError)
			return
		}
		b.sockstatLogger.Flush()
		fmt.Fprintf(w, "logid: %s\n", b.sockstatLogger.LogID())
		fmt.Fprintf(w, "debug info: %v\n", sockstats.DebugInfo())
	default:
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}

func (b *LocalBackend) handleC2NUpdateGet(w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /update received")

	res := b.newC2NUpdateResponse()
	res.Started = b.c2nUpdateStarted()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (b *LocalBackend) handleC2NUpdatePost(w http.ResponseWriter, r *http.Request) {
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

	cmd := exec.Command(cmdTS, "update", "--yes")
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

func (b *LocalBackend) handleC2NPostureIdentityGet(w http.ResponseWriter, r *http.Request) {
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
	_, err := clientupdate.NewUpdater(clientupdate.Arguments{ForAutoUpdate: true})
	return tailcfg.C2NUpdateResponse{
		Enabled:   envknob.AllowsRemoteUpdate() || prefs.Apply,
		Supported: err == nil,
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
	switch runtime.GOOS {
	case "linux":
		if self == "/usr/sbin/tailscaled" || self == "/usr/bin/tailscaled" {
			return "/usr/bin/tailscale", nil
		}
		if self == "/usr/local/sbin/tailscaled" || self == "/usr/local/bin/tailscaled" {
			return "/usr/local/bin/tailscale", nil
		}
		return "", errors.New("tailscale not found in expected place")
	case "windows":
		dir := filepath.Dir(self)
		ts := filepath.Join(dir, "tailscale.exe")
		if fi, err := os.Stat(ts); err == nil && fi.Mode().IsRegular() {
			return ts, nil
		}
		return "", errors.New("tailscale.exe not found in expected place")
	}
	return "", fmt.Errorf("unsupported OS %v", runtime.GOOS)
}

func (b *LocalBackend) handleC2NWoL(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
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
